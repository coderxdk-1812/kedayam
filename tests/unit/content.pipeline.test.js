// End-to-end pipeline check: sensitive-data engine → arbitration → verdict.
// We verify the contract the content script depends on:
//   DOM extraction → sensitive analysis → arbitration → explanation
import { describe, it, expect } from "vitest";
import { analyzeSensitivePayload } from "../../extension/lib/sensitiveDataEngine.js";
import { analyzeClone } from "../../extension/lib/cloneDetection.js";
import { analyzeAuthLayout } from "../../extension/lib/authLayout.js";
import { explainVerdict } from "../../extension/lib/explanation.js";

describe("content scan pipeline contract", () => {
  it("produces a finite, structured verdict from raw text", () => {
    const v = analyzeSensitivePayload("api key = AKIAABCDEFGHIJKLMNOP");
    expect(v).toMatchObject({
      findings: expect.any(Array),
      detectedTypes: expect.any(Array),
      riskScore: expect.any(Number),
      riskLevel: expect.any(String),
    });
    expect(v.riskScore).toBeGreaterThanOrEqual(0);
    expect(v.riskScore).toBeLessThanOrEqual(1);
  });

  it("clone detector composes with auth-layout corroboration", () => {
    // Simulated cloned Microsoft login on a foreign domain — branding +
    // structural layout must agree before we escalate.
    const ctx = {
      pageOrigin: "https://m1cros0ft-signin.example.org",
      scripts: ["https://m1cros0ft-signin.example.org/app.js"],
      styles: ["https://aadcdn.msauth.net/style.css"],
      images: ["https://aadcdn.msauth.net/logo.png"],
      favicon: "https://aadcdn.msauth.net/favicon.ico",
      title: "Sign in to your Microsoft account",
      visibleText: "Sign in Use your Microsoft account",
      forms: [{ hasPassword: false, hasEmailLike: true, hasOtp: false,
        hiddenCount: 2, fieldsCount: 4 }],
      oauthButtons: [],
      hasLogoImage: true, hasHeading: true, firstFieldKind: "email",
    };
    const c = analyzeClone(ctx);
    expect(c.confidence).toBeGreaterThan(0.5);
    expect(c.layout).toBeTruthy();
  });

  it("explanation contract surfaces headline + bullets", () => {
    const verdict = {
      url: "https://bad.example.com/login", host: "bad.example.com",
      score: 32, status: "dangerous",
      signals: [
        { id: "lookalike", title: "Domain mimics a brand",
          severity: "high", contribution: -25, category: "identity" },
        { id: "clone", title: "Page structurally clones a login",
          severity: "high", contribution: -20, category: "clone" },
      ],
      trustAdds: [],
      arbitration: { rules: [{ id: "credential-clone", cap: 35,
        reason: "credential form on cloned layout" }] },
      phishingConfidence: 0.86, cloneConfidence: 0.74,
    };
    const ex = explainVerdict(verdict);
    expect(ex.headline).toMatch(/dangerous|unusual|safe/i);
    // Calm tone: never SHOUT or use panic words.
    expect(ex.headline).not.toMatch(/DANGER!|HACKERS|!!/);
    expect(ex.bullets.length).toBeGreaterThan(0);
    expect(ex.triggeredRules).toContain("credential-clone");
  });

  it("auth layout match is deterministic given identical input", () => {
    const ctx = {
      title: "Sign in to Coinbase", visibleText: "Sign in coinbase",
      forms: [{ hasPassword: true, hasEmailLike: true, hasOtp: false,
        hiddenCount: 1, fieldsCount: 4 }],
      oauthButtons: [], hasLogoImage: true, hasHeading: true,
      firstFieldKind: "email",
    };
    const a = analyzeAuthLayout(ctx);
    const b = analyzeAuthLayout(ctx);
    expect(a).toEqual(b);
  });
});
