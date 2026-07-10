import { describe, it, expect } from "vitest";
import { explainVerdict } from "../../extension/lib/explanation.js";

const sampleVerdict = {
  url: "https://m1cr0soft-login.example/",
  host: "m1cr0soft-login.example",
  root: "example",
  score: 18,
  status: "dangerous",
  phishingConfidence: 0.91,
  cloneConfidence: 0.4,
  signals: [
    {
      id: "lookalike",
      title: "Visually resembles Microsoft",
      severity: "critical",
      category: "identity",
      contribution: -40,
      detail: "punycode",
    },
    {
      id: "credential-form",
      title: "Login form on an unverified domain",
      severity: "high",
      category: "behavior",
      contribution: -22,
    },
    {
      id: "https-trust",
      title: "Encrypted connection",
      severity: "info",
      category: "trust",
      contribution: 10,
    },
  ],
  trustAdds: [{ id: "https-trust", title: "Encrypted connection (HTTPS)", contribution: 10 }],
  arbitration: {
    rules: [
      {
        id: "lookalike-creds",
        cap: 25,
        force: "dangerous",
        reason: "Hostname mimics a known brand and is collecting credentials.",
      },
      { id: "unknown-login", cap: 60, reason: "Credential form on an unverified domain." },
    ],
  },
};

describe("explainVerdict", () => {
  it("returns the stable contract shape", () => {
    const x = explainVerdict(sampleVerdict);
    expect(x).toHaveProperty("verdict", "dangerous");
    expect(x).toHaveProperty("trustScore", 18);
    expect(x.triggeredRules[0]).toBe("lookalike-creds");
    expect(x.contributingRisks[0].id).toBe("lookalike");
    expect(x.contributingTrust[0].id).toBe("https-trust");
    expect(x.headline.toLowerCase()).toContain("dangerous");
    expect(x.bullets.length).toBeGreaterThan(0);
  });

  it("falls back gracefully on empty input", () => {
    const x = explainVerdict(null);
    expect(x.verdict).toBe("suspicious");
    expect(x.bullets).toEqual([]);
  });
});
