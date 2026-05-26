// Calibration regressions — security-research / educational pages must not
// produce dangerous verdicts from visual/textual signals alone, but MUST
// still escalate when real behavioral evidence is present.
import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";
import { analyzeSecurityContext } from "../../extension/lib/securityContext.js";

const settings = {
  detection: { sensitivity: "balanced" },
  apiKeys: { googleSafeBrowsing: "", virusTotal: "" },
  allowlist: [],
};

// ---- shared page-context shapes ----

function researchPage({ title, text, withForm = false }) {
  return {
    pageOrigin: "https://example.org",
    title,
    visibleText: text,
    forms: withForm
      ? [{ action: "/submit", method: "post", hasPassword: false,
          hasEmailLike: true, hasOtp: false, hiddenCount: 0,
          fieldsCount: 1, insideIframe: false }]
      : [],
    hasPasswordField: false,
  };
}

function credentialFormPage({ origin, action }) {
  return {
    pageOrigin: origin,
    title: "Sign in to your Microsoft account",
    visibleText: "outlook office 365 sign in to your account",
    forms: [{ action, method: "post",
      hasPassword: true, hasEmailLike: true, hasOtp: false,
      hiddenCount: 0, fieldsCount: 2, insideIframe: false }],
    hasPasswordField: true,
  };
}

// ---- analyzer unit tests ----

describe("analyzeSecurityContext — scoring buckets", () => {
  it("scores VirusTotal-style content as security-research", () => {
    const s = analyzeSecurityContext({
      host: "www.virustotal.com",
      path: "/gui/url/abc/detection",
      pageContext: {
        title: "URL analysis report — VirusTotal",
        visibleText: "URL scan submitted url analysis indicators of compromise " +
          "malware sample sandbox analysis threat intelligence",
      },
    });
    expect(s.score).toBeGreaterThanOrEqual(0.6);
  });

  it("scores OAuth documentation as educational/auth-docs", () => {
    const s = analyzeSecurityContext({
      host: "docs.stripe.com",
      path: "/docs/connect/oauth-reference",
      pageContext: {
        title: "OAuth 2.0 reference",
        visibleText: "OAuth 2.0 authorization code flow PKCE redirect_uri " +
          "client_id access token tutorial example getting started",
      },
    });
    expect(s.score).toBeGreaterThanOrEqual(0.6);
  });

  it("does NOT flag a plain marketing page as security-context", () => {
    const s = analyzeSecurityContext({
      host: "acme-corp.tld",
      path: "/",
      pageContext: { title: "Welcome", visibleText: "Buy our product today." },
    });
    expect(s.score).toBeLessThan(0.6);
  });

  it("does NOT flag a real phishing page that lacks educational framing", () => {
    const s = analyzeSecurityContext({
      host: "office365-secure-login.tld",
      path: "/",
      pageContext: {
        title: "Sign in to your Microsoft account",
        visibleText: "outlook office 365 sign in to your account",
      },
    });
    expect(s.score).toBeLessThan(0.6);
  });
});

// ---- end-to-end: research/edu pages do not escalate without behavior ----

describe("calibration — security/research pages without behavioral evidence", () => {
  it("PhishTank-style page is not dangerous", async () => {
    const r = await evaluateUrl("https://www.phishtank.org/phish_detail.php?phish_id=123", {
      settings,
      pageContext: researchPage({
        title: "PhishTank — Suspected Phishing URL Submission",
        text: "phishing url indicators of compromise threat intelligence " +
          "submitted url analysis report scan report ioc abuse.ch",
      }),
    });
    expect(r.status).not.toBe("dangerous");
  });

  it("VirusTotal URL report stays safe/informational", async () => {
    const r = await evaluateUrl("https://www.virustotal.com/gui/url/abc/detection", {
      settings,
      pageContext: researchPage({
        title: "URL analysis report — VirusTotal",
        text: "url scan submitted url analysis indicators of compromise " +
          "malware sample sandbox analysis threat intelligence virustotal",
      }),
    });
    expect(r.status).not.toBe("dangerous");
  });

  it("URLScan submission page stays safe/informational", async () => {
    const r = await evaluateUrl("https://urlscan.io/result/abc-def/", {
      settings,
      pageContext: researchPage({
        title: "urlscan.io — Scan report",
        text: "url scan submission report indicators of compromise threat " +
          "intelligence ioc urlscan",
      }),
    });
    expect(r.status).not.toBe("dangerous");
  });

  it("ANY.RUN sandbox report stays safe/informational", async () => {
    const r = await evaluateUrl("https://app.any.run/tasks/abc/", {
      settings,
      pageContext: researchPage({
        title: "ANY.RUN sandbox analysis",
        text: "sandbox analysis malware sample detonation indicators of " +
          "compromise threat intelligence any.run",
      }),
    });
    expect(r.status).not.toBe("dangerous");
  });

  it("GitHub OAuth demo repo page is not dangerous", async () => {
    const r = await evaluateUrl("https://github.com/acme/oauth-demo/blob/main/README.md", {
      settings,
      pageContext: researchPage({
        title: "oauth-demo — sample app",
        text: "tutorial example demo getting started OAuth 2.0 " +
          "authorization code flow redirect_uri client_id access token",
      }),
    });
    expect(r.status).not.toBe("dangerous");
  });

  it("Stripe OAuth docs are not dangerous", async () => {
    const r = await evaluateUrl("https://docs.stripe.com/connect/oauth-reference", {
      settings,
      pageContext: researchPage({
        title: "OAuth 2.0 — Stripe Documentation",
        text: "documentation reference tutorial example OAuth 2.0 " +
          "authorization code flow PKCE redirect_uri client_id access token",
      }),
    });
    expect(r.status).not.toBe("dangerous");
  });

  it("phishing-awareness training page is not dangerous", async () => {
    const r = await evaluateUrl("https://acme-security-training.tld/awareness/lesson-3", {
      settings,
      pageContext: researchPage({
        title: "Phishing awareness training — lesson 3",
        text: "phishing awareness security training tutorial demo example " +
          "phishing campaign indicators of compromise simulation exercise",
      }),
    });
    expect(r.status).not.toBe("dangerous");
  });
});

// ---- regression: behavioral evidence still escalates ----

describe("calibration — behavioral evidence still escalates research-flavored pages", () => {
  it("research-flavored page with off-domain credential POST is dangerous", async () => {
    const ctx = credentialFormPage({
      origin: "https://phishing-awareness-portal.tld",
      action: "https://collector.tld/grab",
    });
    ctx.title = "Phishing awareness training login";
    ctx.visibleText = "phishing awareness security training tutorial example " +
      "sign in to your account " + ctx.visibleText;
    const r = await evaluateUrl("https://phishing-awareness-portal.tld/login", {
      settings, pageContext: ctx,
    });
    expect(r.status).toBe("dangerous");
  });

  it("research-flavored page with cross-origin credential iframe is dangerous", async () => {
    const r = await evaluateUrl("https://security-research-portal.tld/login", {
      settings,
      pageContext: {
        pageOrigin: "https://security-research-portal.tld",
        title: "OAuth tutorial — sign in",
        visibleText: "tutorial demo example OAuth 2.0 authorization code flow " +
          "sign in to continue",
        forms: [{ action: "/login", method: "post",
          hasPassword: true, hasEmailLike: true, hasOtp: false,
          hiddenCount: 0, fieldsCount: 2, insideIframe: true,
          frameOriginCrossDomain: true }],
        hasPasswordField: true,
        iframes: [{ origin: "https://collector.tld", hasPassword: true,
          crossOrigin: true }],
      },
    });
    expect(r.status).toBe("dangerous");
  });

  it("real phishing fixtures remain dangerous (no dampening regression)", async () => {
    const r = await evaluateUrl("https://office365-secure-login.tld/", {
      settings,
      pageContext: credentialFormPage({
        origin: "https://office365-secure-login.tld",
        action: "/login",
      }),
    });
    expect(r.status).toBe("dangerous");
  });
});
