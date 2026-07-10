// Red team — DOM evasion. Phishing kits actively try to hide auth flows
// from extension content scripts. These tests assert that the analyzers
// either detect the evasion, or — when detection is structurally
// impossible — fail safely (no crash, no leak, no false negative escalation).
import { describe, it, expect } from "vitest";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";
import { analyzeAuthLayout } from "../../extension/lib/authLayout.js";
import { analyzeClone } from "../../extension/lib/cloneDetection.js";

function withForms(extra) {
  return {
    pageOrigin: "https://attacker.example.com",
    title: "Sign in",
    visibleText: "Sign in to continue",
    forms: [],
    oauthButtons: [],
    hasLogoImage: true,
    hasHeading: true,
    scripts: [],
    styles: [],
    images: [],
    ...extra,
  };
}

describe("red team — DOM evasion", () => {
  it("password field injected after first render is still classified as auth", () => {
    const ctx = withForms({
      forms: [
        {
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 0,
          fieldsCount: 2,
          action: "https://attacker.example.com/x",
          method: "post",
        },
      ],
      hasPasswordField: true,
      firstFieldKind: "email",
    });
    const r = analyzePhishing(ctx);
    expect(r.authRisk).not.toBe("none");
  });

  it("obfuscated input names (random ids) still trigger auth detection", () => {
    const ctx = withForms({
      forms: [
        {
          hasPassword: true,
          hasEmailLike: false,
          hasOtp: false,
          hiddenCount: 4,
          fieldsCount: 6,
          action: "",
          method: "post",
        },
      ],
      hasPasswordField: true,
    });
    const r = analyzePhishing(ctx);
    expect(r.authRisk).not.toBe("none");
  });

  it("detached / shadow-DOM forms missed by extraction do not crash analyzers", () => {
    // Simulated: extraction returns no forms (shadow root never enumerated).
    const ctx = withForms({ forms: [], hasPasswordField: false });
    expect(() => analyzePhishing(ctx)).not.toThrow();
    expect(() => analyzeAuthLayout(ctx)).not.toThrow();
    expect(() => analyzeClone(ctx)).not.toThrow();
  });

  it("dynamically swapped form action still flagged when off-domain", () => {
    const ctx = withForms({
      pageOrigin: "https://google-secure-login.bad.example",
      forms: [
        {
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 1,
          fieldsCount: 3,
          action: "https://collector.elsewhere.tld/steal",
          method: "post",
        },
      ],
      hasPasswordField: true,
      firstFieldKind: "email",
      visibleText: "Sign in to your Google account",
    });
    const r = analyzePhishing(ctx);
    expect(r.externalFormPost || r.credentialHarvest).toBeTruthy();
  });
});
