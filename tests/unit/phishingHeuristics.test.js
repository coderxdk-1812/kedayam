import { describe, it, expect } from "vitest";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";

describe("analyzePhishing", () => {
  it("returns empty for no context", () => {
    const r = analyzePhishing({});
    expect(r.confidence).toBe(0);
    expect(r.signals.length).toBe(0);
  });

  it("does not flag a login form on a trusted provider", () => {
    const r = analyzePhishing({
      pageOrigin: "https://accounts.google.com",
      title: "Sign in - Google Accounts",
      visibleText: "Sign in to your Google Account",
      forms: [
        {
          action: "/signin",
          method: "post",
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 2,
          fieldsCount: 3,
          insideIframe: false,
        },
      ],
      hasPasswordField: true,
    });
    expect(r.credentialHarvest).toBe(false);
    expect(r.cap).toBeNull();
    expect(r.forceStatus).toBeNull();
  });

  it("flags credential harvest on an unknown domain", () => {
    const r = analyzePhishing({
      pageOrigin: "https://my-secure-portal.tld",
      title: "Login",
      visibleText: "please sign in",
      forms: [
        {
          action: "/post",
          method: "post",
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 0,
          fieldsCount: 2,
          insideIframe: false,
        },
      ],
      hasPasswordField: true,
    });
    expect(r.credentialHarvest).toBe(true);
    expect(r.cap).toBeLessThanOrEqual(70);
  });

  it("escalates to dangerous when impersonating Microsoft", () => {
    const r = analyzePhishing({
      pageOrigin: "https://office365-secure-login.tld",
      title: "Sign in to your Microsoft account",
      visibleText: "outlook office 365 sign in to your account",
      forms: [
        {
          action: "/login",
          method: "post",
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 0,
          fieldsCount: 2,
          insideIframe: false,
        },
      ],
      hasPasswordField: true,
    });
    expect(r.brandImpersonation?.brand).toBe("microsoft.com");
    expect(r.credentialHarvest).toBe(true);
    expect(r.forceStatus).toBe("dangerous");
    expect(r.cap).toBeLessThanOrEqual(25);
  });

  it("escalates to dangerous when form action is off-domain", () => {
    const r = analyzePhishing({
      pageOrigin: "https://login-portal.tld",
      title: "Login",
      visibleText: "log in",
      forms: [
        {
          action: "https://evil-collector.tld/grab",
          method: "post",
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 0,
          fieldsCount: 2,
          insideIframe: false,
        },
      ],
      hasPasswordField: true,
    });
    expect(r.externalFormPost).toBe(true);
    expect(r.forceStatus).toBe("dangerous");
  });

  it("flags javascript: form actions", () => {
    const r = analyzePhishing({
      pageOrigin: "https://something.tld",
      forms: [
        {
          action: "javascript:void(0)",
          method: "post",
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 0,
          fieldsCount: 2,
          insideIframe: false,
        },
      ],
      hasPasswordField: true,
    });
    expect(r.signals.some((s) => s.id === "form-javascript")).toBe(true);
  });

  it("does NOT flag brand impersonation for a bare brand mention with no credential capture", () => {
    // A page that merely talks about a brand — a forum post, a news article, a
    // scam-warning page — is not impersonation and must not be penalized.
    // (Regression guard for the news/blog/forum false-positive class.)
    const r = analyzePhishing({
      pageOrigin: "https://random-domain.tld",
      title: "PayPal account update",
      visibleText: "Confirm your PayPal account or it will be suspended.",
      forms: [],
    });
    expect(r.brandImpersonation).toBe(null);
    expect(r.signals.some((s) => s.id === "brand-impersonation")).toBe(false);
  });

  it("flags brand impersonation when brand text is paired with a credential prompt", () => {
    const r = analyzePhishing({
      pageOrigin: "https://random-domain.tld",
      title: "PayPal account update",
      visibleText: "Confirm your PayPal account password or it will be suspended.",
      hasPasswordField: true,
      forms: [
        {
          action: "/steal",
          method: "post",
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 0,
          fieldsCount: 2,
          insideIframe: false,
        },
      ],
    });
    expect(r.brandImpersonation?.brand).toBe("paypal.com");
    expect(r.cap).toBeLessThanOrEqual(50);
  });

  it("does not impersonate if the page is on a brand alias", () => {
    const r = analyzePhishing({
      pageOrigin: "https://www.paypal.com",
      title: "PayPal sign in",
      visibleText: "Log in to your PayPal account",
      forms: [
        {
          action: "/login",
          method: "post",
          hasPassword: true,
          hasEmailLike: true,
          hasOtp: false,
          hiddenCount: 0,
          fieldsCount: 2,
          insideIframe: false,
        },
      ],
      hasPasswordField: true,
    });
    expect(r.brandImpersonation).toBeNull();
    expect(r.credentialHarvest).toBe(false);
  });
});
