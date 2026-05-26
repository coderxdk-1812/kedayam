// Kedayam — TRUSTED ROOTS REGRESSION SUITE (G5).
//
// CONTRACT: trusted high-reputation domains must NEVER trigger "dangerous"
// or "critical" verdicts from clone / layout / visual-similarity signals
// alone. Visual heuristics must require independent behavioral evidence
// before they can lower a trusted root below the warning threshold.
//
// This file is MANDATORY for every release. If you change clone weighting,
// arbitration ordering, or safelist enforcement, these assertions must
// still hold.

import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const settings = {
  detection: { sensitivity: "balanced", cloneDetection: true },
  apiKeys: { googleSafeBrowsing: "", virusTotal: "" },
  allowlist: [],
};

// Reproduces the github.com false-positive: assets and favicon legitimately
// served from a sibling domain (githubassets.com), plus a login form.
function brandPageContext(origin, brandCdn, opts = {}) {
  return {
    pageOrigin: origin,
    title: opts.title || "Sign in",
    visibleText: opts.visibleText || "sign in to your account",
    favicon: `${brandCdn}/favicon.ico`,
    scripts: [
      `${brandCdn}/app-1.js`, `${brandCdn}/app-2.js`,
      `${brandCdn}/app-3.js`, `${brandCdn}/vendor.js`,
    ],
    styles: [`${brandCdn}/main.css`, `${brandCdn}/theme.css`],
    images: [`${brandCdn}/logo.svg`],
    hasPasswordField: opts.hasPasswordField !== false,
    forms: opts.forms || [{
      action: "/session", method: "post",
      hasPassword: true, hasEmailLike: true, hasOtp: false,
      hiddenCount: 2, fieldsCount: 4, insideIframe: false,
    }],
  };
}

const TRUSTED = [
  { name: "GitHub",       url: "https://github.com/login",
    ctx: brandPageContext("https://github.com", "https://github.githubassets.com") },
  { name: "Gmail",        url: "https://mail.google.com/mail/u/0/",
    ctx: brandPageContext("https://mail.google.com", "https://ssl.gstatic.com",
      { title: "Gmail", visibleText: "sign in to gmail" }) },
  { name: "Google Docs",  url: "https://docs.google.com/document/d/abc",
    ctx: brandPageContext("https://docs.google.com", "https://ssl.gstatic.com",
      { title: "Google Docs", hasPasswordField: false, forms: [] }) },
  { name: "Microsoft 365", url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    ctx: brandPageContext("https://login.microsoftonline.com",
      "https://aadcdn.msftauth.net", { title: "Sign in to your account" }) },
  { name: "Stripe",       url: "https://dashboard.stripe.com/login",
    ctx: brandPageContext("https://dashboard.stripe.com", "https://js.stripe.com",
      { title: "Sign in to Stripe" }) },
  { name: "PayPal",       url: "https://www.paypal.com/signin",
    ctx: brandPageContext("https://www.paypal.com", "https://www.paypalobjects.com",
      { title: "Log in to PayPal" }) },
  { name: "AWS Console",  url: "https://console.aws.amazon.com/console/home",
    ctx: brandPageContext("https://console.aws.amazon.com", "https://a0.awsstatic.com",
      { title: "AWS Management Console" }) },
  { name: "Cloudflare",   url: "https://dash.cloudflare.com/login",
    ctx: brandPageContext("https://dash.cloudflare.com", "https://static.cloudflareinsights.com",
      { title: "Sign in to Cloudflare" }) },
  { name: "Okta",         url: "https://acme.okta.com/login/login.htm",
    ctx: brandPageContext("https://acme.okta.com", "https://ok11static.oktacdn.com",
      { title: "Sign In" }) },
  { name: "Slack",        url: "https://app.slack.com/signin",
    ctx: brandPageContext("https://app.slack.com", "https://a.slack-edge.com",
      { title: "Sign in to Slack" }) },
  { name: "Notion",       url: "https://www.notion.so/login",
    ctx: brandPageContext("https://www.notion.so", "https://www.notion.so/images",
      { title: "Log in - Notion" }) },
  { name: "Figma",        url: "https://www.figma.com/login",
    ctx: brandPageContext("https://www.figma.com", "https://static.figma.com",
      { title: "Sign in to Figma" }) },
];

describe("REGRESSION: trusted roots (G5)", () => {
  for (const { name, url, ctx } of TRUSTED) {
    describe(name, () => {
      it("never returns dangerous", async () => {
        const r = await evaluateUrl(url, { settings, pageContext: ctx });
        expect(r.status, `${name} verdict was ${r.status}`).not.toBe("dangerous");
      });
      it("never returns critical-severity clone-only escalation", async () => {
        const r = await evaluateUrl(url, { settings, pageContext: ctx });
        const cloneSig = (r.signals || []).find((s) => s.id === "clone");
        if (cloneSig) {
          // On trusted roots, the clone signal must surface as informational
          // and contribute zero penalty.
          expect(cloneSig.severity).toBe("info");
          expect(Math.abs(cloneSig.contribution)).toBe(0);
        }
      });
      it("maintains trust floor (>= 80)", async () => {
        const r = await evaluateUrl(url, { settings, pageContext: ctx });
        expect(r.score, `${name} scored ${r.score}/100`).toBeGreaterThanOrEqual(80);
      });
      it("does not force any blocking forceStatus", async () => {
        const r = await evaluateUrl(url, { settings, pageContext: ctx });
        expect(r.arbitration?.forceStatus).toBeNull();
      });
    });
  }
});

describe("REGRESSION: trusted root + behavioral evidence still escalates", () => {
  it("github.com with off-domain credential POST IS dangerous", async () => {
    const ctx = brandPageContext("https://github.com",
      "https://github.githubassets.com");
    ctx.forms = [{
      action: "https://attacker.tld/collect", method: "post",
      hasPassword: true, hasEmailLike: true, hasOtp: false,
      hiddenCount: 0, fieldsCount: 2, insideIframe: false,
    }];
    const r = await evaluateUrl("https://github.com/login",
      { settings, pageContext: ctx });
    expect(r.status).toBe("dangerous");
  });
});
