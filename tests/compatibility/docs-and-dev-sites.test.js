// Compatibility — developer & docs sites must not produce warnings even
// when their content contains real-looking secrets in code blocks.
import { describe, it, expect } from "vitest";
import { analyzeSensitivePayload } from "../../extension/lib/sensitiveDataEngine.js";

const DOC_SAMPLES = [
  // GitHub README
  `## Setup\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=your_secret_here`,
  // Stripe docs
  `const stripe = require('stripe')('sk_test_your_key_here'); // see docs`,
  // OpenAI tutorial
  `import openai\nopenai.api_key = "sk-YOUR_KEY_HERE" # process.env.OPENAI_API_KEY`,
  // StackOverflow snippet
  `curl -X POST -H "Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxx" https://api.example.com`,
  // Payment test card placeholders
  `Use card 4242 4242 4242 4242 with any future expiry for testing.`,
];

describe("compatibility — docs/dev sites do not produce live findings", () => {
  for (const [i, text] of DOC_SAMPLES.entries()) {
    it(`sample ${i + 1} has no live high-confidence findings`, () => {
      const v = analyzeSensitivePayload(text);
      const live = v.findings.filter((f) => !f.suppressed && f.confidence >= 0.85);
      expect(live.length).toBe(0);
    });
  }

  it("aggregate false-positive rate across all samples stays under 5%", () => {
    let live = 0,
      total = 0;
    for (const text of DOC_SAMPLES) {
      const v = analyzeSensitivePayload(text);
      total += v.findings.length;
      live += v.findings.filter((f) => !f.suppressed && f.confidence >= 0.85).length;
    }
    const rate = total ? live / total : 0;
    expect(rate).toBeLessThan(0.05);
  });
});
