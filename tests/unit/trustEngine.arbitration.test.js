import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const settings = {
  detection: { sensitivity: "balanced" },
  apiKeys: { googleSafeBrowsing: "", virusTotal: "" },
  allowlist: [],
};

describe("trust engine arbitration", () => {
  it("never marks an unknown HTTPS login page as 100 SAFE", async () => {
    const r = await evaluateUrl("https://my-secure-portal.tld/login", {
      settings,
      pageContext: {
        pageOrigin: "https://my-secure-portal.tld",
        title: "Login",
        visibleText: "please sign in to continue",
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
      },
    });
    expect(r.score).toBeLessThanOrEqual(70);
    expect(r.status).not.toBe("safe");
  });

  it("flags a fake Microsoft login as dangerous", async () => {
    const r = await evaluateUrl("https://office365-secure-login.tld/", {
      settings,
      pageContext: {
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
      },
    });
    expect(r.status).toBe("dangerous");
    expect(r.score).toBeLessThanOrEqual(25);
  });

  it("flags off-domain credential POST as dangerous", async () => {
    const r = await evaluateUrl("https://login-portal.tld/", {
      settings,
      pageContext: {
        pageOrigin: "https://login-portal.tld",
        title: "Login",
        visibleText: "log in",
        forms: [
          {
            action: "https://collector.tld/grab",
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
      },
    });
    expect(r.status).toBe("dangerous");
  });

  it("still trusts legitimate Google sign-in", async () => {
    const r = await evaluateUrl("https://accounts.google.com/signin", {
      settings,
      pageContext: {
        pageOrigin: "https://accounts.google.com",
        title: "Sign in - Google Accounts",
        visibleText: "Sign in to continue to Gmail",
        forms: [
          {
            action: "/signin/v2",
            method: "post",
            hasPassword: true,
            hasEmailLike: true,
            hasOtp: false,
            hiddenCount: 5,
            fieldsCount: 6,
            insideIframe: false,
          },
        ],
        hasPasswordField: true,
      },
    });
    expect(r.status).toBe("safe");
    expect(r.score).toBeGreaterThanOrEqual(85);
  });

  it("respects the allowlist override even with phishing signals", async () => {
    const r = await evaluateUrl("https://office365-secure-login.tld/", {
      settings: { ...settings, allowlist: ["office365-secure-login.tld"] },
      pageContext: {
        pageOrigin: "https://office365-secure-login.tld",
        title: "Sign in to your Microsoft account",
        visibleText: "outlook sign in to your account",
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
      },
    });
    expect(r.score).toBeGreaterThanOrEqual(85);
  });
});
