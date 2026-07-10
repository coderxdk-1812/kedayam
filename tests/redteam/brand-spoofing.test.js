// Red team — brand spoofing & homoglyph attacks.
import { describe, it, expect } from "vitest";
import { lookalikeAnalysis } from "../../extension/lib/lookalike.js";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";

describe("red team — brand spoofing", () => {
  it("homoglyph variant of microsoft is detected", () => {
    const r = lookalikeAnalysis("micros0ft.com");
    expect(r.match || r.confidence > 0.3).toBeTruthy();
  });

  it("punycode IDN spoof is flagged", () => {
    // xn--pple-43d.com is one of the canonical IDN PoCs.
    const r = lookalikeAnalysis("xn--pple-43d.com");
    expect(r.idnSpoof || r.match).toBeTruthy();
  });

  it("partial-brand subdomain on unrelated apex caps trust", () => {
    // The classic "paypal.account-verify.com".
    const r = analyzePhishing({
      pageOrigin: "https://paypal.account-verify.example",
      title: "Log in to PayPal",
      visibleText: "Log in to PayPal",
      forms: [
        { hasPassword: true, hasEmailLike: true, hasOtp: false, hiddenCount: 0, fieldsCount: 2 },
      ],
      hasPasswordField: true,
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
    });
    expect(r.authRisk).not.toBe("none");
    expect(r.brandImpersonation || r.confidence > 0.3).toBeTruthy();
  });

  it("SVG / canvas-only logos still leave brand text detectable", () => {
    // Even if the brand mark is canvas-rendered, the visible heading text
    // gives us a lever. We assert the analyzer keys off TEXT, not <img> alone.
    const r = analyzePhishing({
      pageOrigin: "https://office-secure-login.example",
      title: "Microsoft account verification",
      visibleText: "Use your Microsoft account to continue",
      forms: [
        { hasPassword: true, hasEmailLike: true, hasOtp: false, hiddenCount: 0, fieldsCount: 2 },
      ],
      hasPasswordField: true,
      oauthButtons: [],
      scripts: [],
      styles: [],
      images: [],
    });
    expect(r.brandImpersonation || r.confidence > 0.4).toBeTruthy();
  });
});
