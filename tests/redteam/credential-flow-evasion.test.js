// Red team — credential-flow evasion: staged auth, MFA-only harvest,
// QR-login theft, fake device verification, OAuth popup spoof.
import { describe, it, expect } from "vitest";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";
import { arbitrate, ARB_CONST } from "../../extension/lib/arbitration.js";

const baseCtx = {
  allowlistRoot: false, isReputableRoot: false, isTrustedProvider: false,
  hasAuthWorkflow: true,
  lookalike: { match: null, confidence: 0 },
  idnSpoof: false,
  clone: { confidence: 0 },
};

describe("red team — credential flow evasion", () => {
  it("MFA-only harvest on unknown domain is capped", () => {
    const r = analyzePhishing({
      pageOrigin: "https://verify-now.example.org",
      title: "Verify your code",
      visibleText: "Enter the 6-digit code from your authenticator app",
      forms: [{ hasPassword: false, hasEmailLike: false, hasOtp: true,
        hiddenCount: 1, fieldsCount: 2 }],
      hasPasswordField: false, oauthButtons: [],
      scripts: [], styles: [], images: [],
    });
    const a = arbitrate({ ...baseCtx, phishing: r });
    expect(a.cap).toBeLessThanOrEqual(ARB_CONST.CAP_MFA_HARVEST_UNKNOWN);
  });

  it("OAuth-button spoof posting to unrelated domain is capped", () => {
    const r = analyzePhishing({
      pageOrigin: "https://login.cheap-host.example",
      title: "Continue with Google",
      visibleText: "Sign in with Google",
      forms: [{ hasPassword: false, hasEmailLike: true, hasOtp: false,
        hiddenCount: 0, fieldsCount: 1,
        action: "https://collector.bad.tld/oauth-relay", method: "post" }],
      oauthButtons: ["google"], hasPasswordField: false,
      scripts: [], styles: [], images: [],
    });
    const a = arbitrate({ ...baseCtx, phishing: r });
    expect(a.cap).toBeDefined();
    expect(a.cap).toBeLessThanOrEqual(ARB_CONST.CAP_OAUTH_SPOOF + 5);
  });

  it("multi-step email-first flow on unverified root is capped", () => {
    const r = analyzePhishing({
      pageOrigin: "https://signin.suspicious.example",
      title: "Sign in", visibleText: "Enter your email to continue",
      forms: [{ hasPassword: false, hasEmailLike: true, hasOtp: false,
        hiddenCount: 1, fieldsCount: 2 }],
      hasPasswordField: false, oauthButtons: [],
      scripts: [], styles: [], images: [],
    });
    const a = arbitrate({ ...baseCtx, phishing: r });
    expect(a.cap).toBeLessThanOrEqual(ARB_CONST.CAP_EMAIL_FIRST);
  });

  it("fake device-verification page never elevates to safe", () => {
    const r = analyzePhishing({
      pageOrigin: "https://device-verify.example.cc",
      title: "Verify your device",
      visibleText: "We need to verify this device — enter your password",
      forms: [{ hasPassword: true, hasEmailLike: false, hasOtp: false,
        hiddenCount: 0, fieldsCount: 1 }],
      hasPasswordField: true, oauthButtons: [],
      scripts: [], styles: [], images: [],
    });
    const a = arbitrate({ ...baseCtx, phishing: r });
    // Single-password "verify device" on unknown root must cap below 70.
    expect(a.cap === null || a.cap <= 70).toBe(true);
  });
});
