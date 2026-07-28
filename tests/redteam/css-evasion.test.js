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
  oauthButtons: [],
  scripts: [],
  styles: [],
  images: [],
  hasLogoImage: false,
  hasHeading: true,
};

describe("red team — CSS evasion", () => {
  it("opacity:0 password forms still count as auth workflow", () => {
    // Extractor saw the password input even though CSS hid it visually.
    const r = analyzePhishing({
      ...base,
      forms: [
        { hasPassword: true, hasEmailLike: true, hasOtp: false, hiddenCount: 0, fieldsCount: 2 },
      ],
      hasPasswordField: true,
    });
    expect(r.authRisk).not.toBe("none");
  });

  it("offscreen credential form on unknown root caps trust", () => {
    const r = analyzePhishing({
      ...base,
      forms: [
        { hasPassword: true, hasEmailLike: true, hasOtp: false, hiddenCount: 8, fieldsCount: 10 },
      ],
      hasPasswordField: true,
    });
    // Contract (see file header): a visually-suppressed credential form must
    // never read as "no risk". The bare presence of a password field is now
    // informational (weight 0) — but the credential-harvest FLAG and the auth
    // risk it drives must still be recognized so arbitration can escalate when
    // corroborated. (Hidden-field ratio adds an explicit kit signal when the
    // form also declares an off-domain action; this fixture has none.)
    expect(r.credentialHarvest).toBe(true);
    expect(r.authRisk).not.toBe("none");
  });

  it("invisible iframe credential capture flagged via insideIframe", () => {
    const r = analyzePhishing({
      ...base,
      topLevelIframe: true,
      forms: [
        {
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 0,
          fieldsCount: 2,
          insideIframe: true,
        },
      ],
      hasPasswordField: true,
    });
    expect(r.authRisk).not.toBe("none");
  });
});
