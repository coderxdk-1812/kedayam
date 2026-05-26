// Red team — CSS evasion. Hidden / off-screen / overlay phishing forms.
// We can't always *see* CSS from the analyzer surface, but our pipeline
// must never go from "I saw a password field" to "no risk" just because
// the form is visually suppressed. These tests pin that contract.
import { describe, it, expect } from "vitest";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";

const base = {
  pageOrigin: "https://login-portal.cheap-host.example",
  title: "Account verification",
  visibleText: "Please verify your account to continue",
  oauthButtons: [], scripts: [], styles: [], images: [],
  hasLogoImage: false, hasHeading: true,
};

describe("red team — CSS evasion", () => {
  it("opacity:0 password forms still count as auth workflow", () => {
    // Extractor saw the password input even though CSS hid it visually.
    const r = analyzePhishing({ ...base,
      forms: [{ hasPassword: true, hasEmailLike: true, hasOtp: false,
        hiddenCount: 0, fieldsCount: 2 }],
      hasPasswordField: true });
    expect(r.authRisk).not.toBe("none");
  });

  it("offscreen credential form on unknown root caps trust", () => {
    const r = analyzePhishing({ ...base,
      forms: [{ hasPassword: true, hasEmailLike: true, hasOtp: false,
        hiddenCount: 8, fieldsCount: 10 }],
      hasPasswordField: true });
    // Heavy hidden-input ratio is a known kit signal.
    expect(r.confidence).toBeGreaterThan(0.3);
  });

  it("invisible iframe credential capture flagged via insideIframe", () => {
    const r = analyzePhishing({ ...base,
      topLevelIframe: true,
      forms: [{ hasPassword: true, hasEmailLike: true, hasOtp: false,
        hiddenCount: 0, fieldsCount: 2, insideIframe: true }],
      hasPasswordField: true });
    expect(r.authRisk).not.toBe("none");
  });
});
