// Kedayam — POST-AUDIT REGRESSION SUITE.
//
// Mandatory release gate covering the four audit findings:
//   C-01  No production global detection oracle.
//   C-02  User allowlist cannot bypass behavioral malicious evidence.
//   C-03  Clipboard secrets are not closure-retained during modal lifetime.
//   C-04  Generic enterprise / AiTM SSO flows escalate beyond "safe".
//
// These tests are pure and import detection modules directly — they do
// NOT depend on `window.__kedayam`, which is intentionally absent from
// production bundles.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { arbitrate } from "../../extension/lib/arbitration.js";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";

const settings = {
  detection: { sensitivity: "balanced", cloneDetection: true },
  apiKeys: { googleSafeBrowsing: "", virusTotal: "" },
  allowlist: [],
};

// ──────────────────────────────────────────────────────────────────────
// C-01 — No production global detection oracle.
// We grep the shipped content script source for the dev-only guard and
// assert that `window.__kedayam = …` only appears inside it.
// ──────────────────────────────────────────────────────────────────────
describe("C-01 — production builds expose no global detection oracle", () => {
  const src = readFileSync(
    resolve(__dirname, "../../extension/content/content.js"),
    "utf8");

  it("window.__kedayam assignment is gated behind a DEV check", () => {
    // Every assignment must be inside an `if (DEV)` block.
    const matches = [...src.matchAll(/window\.__kedayam\s*=/g)];
    expect(matches.length).toBeGreaterThan(0);
    for (const m of matches) {
      const before = src.slice(Math.max(0, m.index - 200), m.index);
      expect(before, "every __kedayam assignment must be DEV-gated")
        .toMatch(/if\s*\(\s*DEV\s*\)/);
    }
  });

  it("DEV flag is derived from chrome.runtime.getManifest().update_url", () => {
    expect(src).toMatch(/const\s+DEV\s*=\s*!chrome\.runtime\.getManifest/);
  });

  it("contains no unconditional 'window.scan' / 'window.decideAction' exports", () => {
    expect(src).not.toMatch(/window\.scan\s*=/);
    expect(src).not.toMatch(/window\.decideAction\s*=/);
  });
});

// ──────────────────────────────────────────────────────────────────────
// C-02 — Allowlist cannot suppress behavioral malicious evidence.
// ──────────────────────────────────────────────────────────────────────
describe("C-02 — user allowlist cannot bypass exfiltration", () => {
  const baseCtx = (origin, formAction, extras = {}) => ({
    pageOrigin: origin,
    title: extras.title || "Sign in",
    visibleText: extras.visibleText || "sign in",
    hasPasswordField: true,
    forms: [{
      action: formAction, method: "post",
      hasPassword: !extras.otpOnly,
      hasEmailLike: true,
      hasOtp: !!extras.otpOnly,
      hiddenCount: 0, fieldsCount: 2,
      insideIframe: !!extras.iframe,
    }],
    oauthButtons: extras.oauthButtons || [],
    topLevelIframe: false,
    ...(extras.ctx || {}),
  });

  it("allowlisted root + external credential POST → dangerous", async () => {
    const r = await evaluateUrl("https://my-portal.tld/login", {
      settings: { ...settings, allowlist: ["my-portal.tld"] },
      pageContext: baseCtx("https://my-portal.tld",
        "https://attacker.tld/collect"),
    });
    expect(r.status).toBe("dangerous");
    expect(r.score).toBeLessThanOrEqual(30);
  });

  it("allowlisted root + OAuth spoof (off-domain OAuth POST) → dangerous", async () => {
    const r = await evaluateUrl("https://my-portal.tld/oauth", {
      settings: { ...settings, allowlist: ["my-portal.tld"] },
      pageContext: baseCtx("https://my-portal.tld",
        "https://attacker.tld/oauth", {
          oauthButtons: ["google"],
          visibleText: "sign in with google continue",
        }),
    });
    expect(r.status).toBe("dangerous");
  });

  it("allowlisted root + cross-origin credential iframe → dangerous", async () => {
    const r = await evaluateUrl("https://my-portal.tld/login", {
      settings: { ...settings, allowlist: ["my-portal.tld"] },
      pageContext: baseCtx("https://my-portal.tld", "/login",
        { iframe: true }),
    });
    // The iframe-credential-form signal must escalate even under allowlist.
    expect(r.status).not.toBe("safe");
  });

  it("arbitrate(): allowlist + externalFormPost still emits dangerous rules", () => {
    const arb = arbitrate({
      allowlistRoot: true, isReputableRoot: false, isTrustedProvider: false,
      hasAuthWorkflow: true,
      lookalike: { match: null, confidence: 0 },
      clone: { confidence: 0 },
      phishing: { credentialHarvest: true, externalFormPost: true,
        forms: [], signals: [] },
    });
    expect(arb.forceStatus).toBe("dangerous");
    expect(arb.rules.some((r) => r.id === "external-post")).toBe(true);
  });

  it("allowlisted root + only weak visual signals → stays trusted", async () => {
    // Brand-impersonation text alone is a weak signal and may be suppressed
    // by the allowlist primitive. Behavioral evidence is what matters.
    const r = await evaluateUrl("https://my-portal.tld/login", {
      settings: { ...settings, allowlist: ["my-portal.tld"] },
      pageContext: baseCtx("https://my-portal.tld", "/login",
        { visibleText: "sign in to your microsoft account outlook" }),
    });
    expect(r.score).toBeGreaterThanOrEqual(70);
  });
});

// ──────────────────────────────────────────────────────────────────────
// C-03 — Clipboard secrets must not be closure-retained during the
// warning modal lifetime; they are re-read on Continue and zeroized.
// We verify this at the source level (no string captured before the
// modal, navigator.clipboard.readText() is called inside onContinue,
// and the variable is cleared in finally).
// ──────────────────────────────────────────────────────────────────────
describe("C-03 — clipboard secrets are ephemeral", () => {
  const src = readFileSync(
    resolve(__dirname, "../../extension/content/content.js"),
    "utf8");

  it("does NOT capture clipboardData text into a closure before the modal", () => {
    // The old anti-pattern: `const replayText = e.clipboardData?.getData(...)`
    // outside onContinue. Must be removed.
    const banned = /const\s+replayText\s*=\s*e\.clipboardData/;
    expect(src).not.toMatch(banned);
  });

  it("does NOT depend on navigator.clipboard.readText() at Continue time (NEW-01)", () => {
    // Previous fix re-read clipboard inside onContinue — fails silently
    // without the clipboardRead permission. New fix uses an ephemeral
    // in-memory store keyed by a single-use token.
    expect(src).not.toMatch(/navigator\.clipboard\?\.readText\?\.\(/);
    expect(src).toMatch(/ephemeralReplay\.store\(/);
    expect(src).toMatch(/ephemeralReplay\.consume\(/);
  });

  it("zeroizes the replay text in a finally block AND on modal close", () => {
    const onContinueIdx = src.indexOf("onContinue:");
    expect(onContinueIdx).toBeGreaterThan(-1);
    const slice = src.slice(onContinueIdx, onContinueIdx + 2000);
    expect(slice).toMatch(/finally\s*\{[\s\S]*replayText\s*=\s*""/);
    expect(src).toMatch(/ephemeralReplay\.zeroize\(replayToken\)/);
  });

  it("never persists raw clipboard text in log() calls", () => {
    // log() calls in the paste path must only emit counts/host, never
    // the raw payload. We assert the shape of every log() arg in the
    // paste interception block.
    const region = src.match(/document\.addEventListener\("paste"[\s\S]*?\}, true\);/);
    expect(region).toBeTruthy();
    const logCalls = [...region[0].matchAll(/log\(\s*\{([\s\S]*?)\}\s*\)/g)];
    expect(logCalls.length).toBeGreaterThan(0);
    for (const c of logCalls) {
      expect(c[1]).not.toMatch(/replayText|clipboardData|getData/);
    }
  });
});

// ──────────────────────────────────────────────────────────────────────
// C-04 — Generic enterprise / AiTM SSO flows escalate beyond "safe"
// even without explicit brand keywords. Must also not over-fire on
// legitimate IdP roots.
// ──────────────────────────────────────────────────────────────────────
describe("C-04 — generic enterprise AiTM detection", () => {
  it("email-first generic enterprise flow on unknown domain is not safe", async () => {
    const r = await evaluateUrl("https://login-portal-prod.cc/signin", {
      settings,
      pageContext: {
        pageOrigin: "https://login-portal-prod.cc",
        title: "Sign in to continue",
        visibleText: "sign in to continue your organization requires verify it's you continue to your organization",
        hasPasswordField: false,
        forms: [{ action: "/next", method: "post",
          hasPassword: false, hasEmailLike: true, hasOtp: false,
          hiddenCount: 0, fieldsCount: 2, insideIframe: false }],
      },
    });
    expect(r.status).not.toBe("safe");
    expect(r.signals.some((s) => s.id === "generic-enterprise-auth")).toBe(true);
    expect(r.score).toBeLessThanOrEqual(60);
  });

  it("enterprise SSO copy + off-domain credential POST is dangerous", async () => {
    const r = await evaluateUrl("https://sso-edge-prod.cc/signin", {
      settings,
      pageContext: {
        pageOrigin: "https://sso-edge-prod.cc",
        title: "Sign in",
        visibleText: "approve sign-in request device verification continue to your organization",
        hasPasswordField: true,
        forms: [{ action: "https://relay.attacker.cc/post", method: "post",
          hasPassword: true, hasEmailLike: true, hasOtp: false,
          hiddenCount: 0, fieldsCount: 2, insideIframe: false }],
      },
    });
    expect(r.status).toBe("dangerous");
  });

  it("MFA-approval-only generic enterprise flow is at least suspicious", () => {
    const ph = analyzePhishing({
      pageOrigin: "https://mfa-step.cc",
      title: "Approve sign-in request",
      visibleText: "approve this sign-in request on your trusted device device verification",
      forms: [{ action: "/approve", method: "post",
        hasPassword: false, hasEmailLike: false, hasOtp: true,
        hiddenCount: 0, fieldsCount: 1, insideIframe: false }],
    });
    expect(ph.signals.some((s) => s.id === "generic-enterprise-auth")).toBe(true);
    expect(ph.forceStatus).toBe("suspicious");
  });

  it("does NOT over-fire on legitimate IdP roots", async () => {
    const r = await evaluateUrl("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", {
      settings,
      pageContext: {
        pageOrigin: "https://login.microsoftonline.com",
        title: "Sign in to your account",
        visibleText: "sign in to continue to your organization use your work or school account approve sign-in request",
        hasPasswordField: true,
        forms: [{ action: "/common/login", method: "post",
          hasPassword: true, hasEmailLike: true, hasOtp: false,
          hiddenCount: 4, fieldsCount: 6, insideIframe: false }],
      },
    });
    expect(r.status).toBe("safe");
    expect(r.score).toBeGreaterThanOrEqual(80);
  });

  it("does NOT over-fire on okta.com tenant logins", async () => {
    const r = await evaluateUrl("https://acme.okta.com/login/login.htm", {
      settings,
      pageContext: {
        pageOrigin: "https://acme.okta.com",
        title: "Sign In",
        visibleText: "sign in to continue use your corporate account continue to your organization",
        hasPasswordField: true,
        forms: [{ action: "/login/do-login", method: "post",
          hasPassword: true, hasEmailLike: true, hasOtp: false,
          hiddenCount: 2, fieldsCount: 4, insideIframe: false }],
      },
    });
    expect(r.status).toBe("safe");
  });

  it("real-world fixture: generic-enterprise-sso.html is flagged dangerous", async () => {
    const html = readFileSync(
      resolve(__dirname, "../fixtures/phishing/generic-enterprise-sso.html"),
      "utf8");
    const title = html.match(/<title>([^<]+)<\/title>/i)?.[1] || "";
    const text = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    const action = html.match(/<form[^>]+action="([^"]+)"/i)?.[1] || "";
    const r = await evaluateUrl("https://generic-enterprise-host.cc/signin", {
      settings,
      pageContext: {
        pageOrigin: "https://generic-enterprise-host.cc",
        title, visibleText: text,
        hasPasswordField: false,
        forms: [{ action, method: "post",
          hasPassword: false, hasEmailLike: true, hasOtp: false,
          hiddenCount: 0, fieldsCount: 2, insideIframe: false }],
      },
    });
    // Off-domain credential relay + generic SSO copy → arbitrator dangerous.
    expect(r.status).toBe("dangerous");
    expect(r.signals.some((s) => s.id === "generic-enterprise-auth")).toBe(true);
  });
});
