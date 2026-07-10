import { describe, it, expect } from "vitest";
import { arbitrate, ARB_CONST } from "../../extension/lib/arbitration.js";

const base = {
  lookalike: { match: null, confidence: 0 },
  clone: { confidence: 0 },
  phishing: { confidence: 0, forms: [] },
};

describe("arbitration v2 — new dangerous rules", () => {
  it("mfa-harvest fires on OTP-only form on unknown domain", () => {
    const r = arbitrate({ ...base, hasAuthWorkflow: true, mfaOnly: true });
    expect(r.forceStatus).toBe("dangerous");
    expect(r.rules.some((x) => x.id === "mfa-harvest")).toBe(true);
    expect(r.cap).toBeLessThanOrEqual(ARB_CONST.CAP_MFA_HARVEST_UNKNOWN);
  });

  it("cross-origin-credentials fires when password sits in cross-origin iframe", () => {
    const r = arbitrate({
      ...base,
      hasAuthWorkflow: true,
      phishing: {
        ...base.phishing,
        credentialHarvest: true,
        signals: [{ id: "iframe-credential-form" }],
      },
    });
    expect(r.rules.some((x) => x.id === "cross-origin-credentials")).toBe(true);
    expect(r.cap).toBeLessThanOrEqual(ARB_CONST.CAP_CROSS_ORIGIN_CREDS);
  });

  it("oauth-spoof fires on external POST + OAuth button", () => {
    const r = arbitrate({
      ...base,
      hasAuthWorkflow: true,
      phishing: {
        ...base.phishing,
        credentialHarvest: true,
        externalFormPost: true,
        signals: [{ id: "oauth-impersonation" }],
      },
    });
    expect(r.rules.some((x) => x.id === "oauth-spoof")).toBe(true);
    expect(r.forceStatus).toBe("dangerous");
  });

  it("auth-layout-clone is suspicious-only without behavioral evidence", () => {
    const r = arbitrate({
      ...base,
      hasAuthWorkflow: true,
      authLayout: { isLayoutClone: true, confidence: 0.85, matchedTemplate: "microsoft" },
    });
    // Layout similarity alone never escalates to dangerous (G4 sanity).
    expect(r.forceStatus).not.toBe("dangerous");
    expect(r.rules.some((x) => x.id === "auth-layout-soft-unknown")).toBe(true);
  });

  it("auth-layout-clone DOES fire dangerous when paired with external POST", () => {
    const r = arbitrate({
      ...base,
      hasAuthWorkflow: true,
      authLayout: { isLayoutClone: true, confidence: 0.85, matchedTemplate: "microsoft" },
      phishing: { ...base.phishing, credentialHarvest: true, externalFormPost: true },
    });
    expect(r.rules.some((x) => x.id === "auth-layout-clone")).toBe(true);
    expect(r.forceStatus).toBe("dangerous");
  });

  it("hidden-overlay caps trust on unknown roots", () => {
    const r = arbitrate({ ...base, hiddenLoginOverlay: true });
    expect(r.rules.some((x) => x.id === "hidden-overlay")).toBe(true);
  });

  it("email-first caps trust at email-only capture", () => {
    const r = arbitrate({ ...base, emailFirstFlow: true });
    expect(r.rules.some((x) => x.id === "email-first")).toBe(true);
    expect(r.cap).toBeLessThanOrEqual(ARB_CONST.CAP_EMAIL_FIRST);
  });

  it("allowlist still short-circuits even when new rules would fire", () => {
    const r = arbitrate({ ...base, allowlistRoot: true, mfaOnly: true, hiddenLoginOverlay: true });
    expect(r.cap).toBeNull();
  });
});
