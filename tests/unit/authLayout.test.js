import { describe, it, expect } from "vitest";
import {
  fingerprintAuthLayout,
  matchAuthTemplate,
  analyzeAuthLayout,
} from "../../extension/lib/authLayout.js";

const microsoftLike = {
  pageOrigin: "https://m1cr0soft-login.example/",
  title: "Sign in",
  visibleText: "Sign in to your Microsoft account. No account? Create one.",
  forms: [
    { hasPassword: false, hasEmailLike: true, hasOtp: false, hiddenCount: 4, fieldsCount: 8 },
  ],
  oauthButtons: [],
  hasLogoImage: true,
  hasHeading: true,
  firstFieldKind: "email",
};

describe("authLayout — fingerprint + match", () => {
  it("builds a sensible signature for a Microsoft-like login", () => {
    const fp = fingerprintAuthLayout(microsoftLike);
    expect(fp.signature[0]).toBe("logo");
    expect(fp.signature).toContain("email");
    expect(fp.signature).toContain("next");
    expect(fp.hasPasswordSplit).toBe(true);
  });

  it("matches the Microsoft template with high confidence", () => {
    const fp = fingerprintAuthLayout(microsoftLike);
    const m = matchAuthTemplate(fp, microsoftLike);
    expect(m.template?.id).toBe("microsoft");
    expect(m.confidence).toBeGreaterThanOrEqual(0.7);
  });

  it("does not match anything for an empty page", () => {
    const r = analyzeAuthLayout({ pageOrigin: "https://x/" });
    expect(r.matchedTemplate).toBe(null);
    expect(r.isLayoutClone).toBe(false);
  });

  it("flags a clone of Google's email-first flow", () => {
    const r = analyzeAuthLayout({
      pageOrigin: "https://g00gle-accounts.example/",
      title: "Sign in",
      visibleText: "Sign in. Use your Google account. Forgot email?",
      forms: [
        { hasPassword: false, hasEmailLike: true, hasOtp: false, hiddenCount: 2, fieldsCount: 6 },
      ],
      oauthButtons: [],
      hasLogoImage: true,
      hasHeading: true,
      firstFieldKind: "email",
    });
    expect(r.matchedTemplate).toBe("google");
    expect(r.isLayoutClone).toBe(true);
  });
});
