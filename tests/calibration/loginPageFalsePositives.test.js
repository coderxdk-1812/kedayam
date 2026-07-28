// Calibration — legit login-page false positives (issue NEW-04).
//
// Testers reported ordinary, legitimate sites (unlisted banks, SaaS, company
// SSO) reading as "suspicious"/medium-risk. Root causes were:
//   1. `phishing.cap = 60` applied unconditionally to ANY credential form,
//      bypassing arbitration's corroboration gate.
//   2. A heavy `credential-form` penalty for the bare presence of a password.
//   3. "urgent authentication phrasing" firing on benign "sign in"/"login".
//   4. `auth-keyword` firing on normal `login.*` / `secure.*` subdomains.
//
// These regressions pin the fixed contract: a clean, same-origin HTTPS login on
// an unlisted domain is SAFE, while every real phishing tell still escalates.
import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const settings = { detection: { sensitivity: "balanced" } };

// A realistic (resource-rich) login page, so the on-device kit classifier —
// which keys off sparse/bare structure — does not skew the fixture.
function loginPage(host, over = {}) {
  return {
    pageOrigin: `https://${host}`,
    title: over.title || `${host} — Sign in`,
    visibleText:
      over.text ||
      "Sign in to your account. Email address Password Forgot your password? Create an account. Terms Privacy Help Contact Support",
    hasPasswordField: over.pwd !== false,
    scripts: Array.from({ length: 12 }, (_, i) => `https://${host}/assets/app.${i}.js`),
    images: Array.from({ length: 8 }, (_, i) => `https://${host}/img/${i}.png`),
    links: Array.from({ length: 20 }, (_, i) => `https://${host}/page${i}`),
    styles: [`https://${host}/app.css`],
    forms: [
      {
        action: over.action || `https://${host}/login`,
        method: "post",
        hasPassword: over.pwd !== false,
        hasEmailLike: true,
        hasOtp: false,
        fieldCount: 3,
        hiddenFields: 0,
      },
    ],
    oauthButtons: [],
    authFlow: { anomalies: [], state: "login" },
  };
}

const scoreOf = async (host, over) => {
  const ctx = loginPage(host, over);
  return evaluateUrl(ctx.pageOrigin + "/login", {
    settings,
    pageContext: ctx,
    authFlow: ctx.authFlow,
  });
};

describe("legit login pages are safe (NEW-04)", () => {
  it("clean same-origin login on an unlisted domain reads safe", async () => {
    const r = await scoreOf("app.mytool.io");
    expect(r.status).toBe("safe");
    expect(r.score).toBeGreaterThanOrEqual(71);
  });

  it("the bare presence of a password form is informational, not a penalty", async () => {
    const r = await scoreOf("app.mytool.io");
    // credential-form must be recognized (drives arbitration) but contribute 0.
    const cf = (r.signals || []).find((s) => s.id === "credential-form");
    expect(cf).toBeTruthy();
    expect(cf.contribution || 0).toBe(0);
    // …and it must not impose an unconditional cap on its own.
    const caps = (r.signals || []).filter((s) => s.cap).map((s) => s.maxScore);
    expect(Math.min(100, ...caps.concat(100))).toBeGreaterThan(60);
  });

  it("company SSO on a login.* subdomain is not penalized for the subdomain", async () => {
    const r = await scoreOf("login.bigcorp-example.com", {
      text: "Sign in with your work account. Password Continue Help",
    });
    expect(r.status).toBe("safe");
    // The auth-keyword penalty must NOT fire on a bare login.* subdomain.
    expect((r.signals || []).some((s) => s.id === "auth-keyword")).toBe(false);
  });

  it("secure.* subdomain login is not flagged by the hostname keyword", async () => {
    const r = await scoreOf("secure.acmesavings.com");
    expect((r.signals || []).some((s) => s.id === "auth-keyword")).toBe(false);
    expect(r.status).not.toBe("dangerous");
  });

  it("benign login copy does not trigger urgent-phrasing", async () => {
    const r = await scoreOf("portal.exampleco.com", {
      text: "Sign in. Log in. Login. Forgot password? Two-factor authentication. OTP.",
    });
    expect((r.signals || []).some((s) => s.id === "auth-phrasing")).toBe(false);
  });
});

describe("real phishing tells still escalate (NEW-04 must not weaken detection)", () => {
  it("off-domain credential POST is dangerous", async () => {
    const r = await scoreOf("secure-portal.example", {
      action: "https://collector.evil.io/steal",
    });
    expect(r.status).toBe("dangerous");
  });

  it("a brand-lookalike login domain is dangerous", async () => {
    const r = await scoreOf("paypal-login.example", {
      title: "PayPal",
      text: "Sign in to PayPal. Password",
    });
    expect(r.status).toBe("dangerous");
  });

  it("auth keyword in the registrable label still fires (non-lookalike)", async () => {
    // "verify" is in the registrable label itself — a real tell, unlike a bare
    // login.* subdomain. (No brand, so it isn't suppressed by the lookalike gate.)
    const r = await scoreOf("verify-portal-signin.example");
    expect((r.signals || []).some((s) => s.id === "auth-keyword")).toBe(true);
  });

  it("brand-impersonation login with coercive phrasing is not safe", async () => {
    const r = await scoreOf("office365-verify.example", {
      title: "Microsoft Sign in",
      text: "Unusual activity detected. Verify your account to avoid suspension. Password Microsoft account",
    });
    expect(r.status).not.toBe("safe");
    expect((r.signals || []).some((s) => s.id === "auth-phrasing")).toBe(true);
  });
});
