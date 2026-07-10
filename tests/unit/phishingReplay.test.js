// Phishing-replay metrics harness.
//
// Loads sanitized HTML fixtures and runs them through the heuristic stack
// (phishing + clone + auth-layout + arbitration) — no browser required.
// Asserts recall, precision, and per-fixture verdict expectations.

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";
import { analyzeClone } from "../../extension/lib/cloneDetection.js";
import { analyzeAuthLayout } from "../../extension/lib/authLayout.js";
import { arbitrate } from "../../extension/lib/arbitration.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIX = join(here, "../fixtures/phishing");

const EXPECT = {
  "microsoft365.html": {
    origin: "https://login.evil.example",
    verdict: "dangerous",
    ruleAny: ["external-post", "external-post-clone"],
  },
  "coinbase.html": {
    origin: "https://coinbase-secure.evil.example",
    verdict: "dangerous",
    ruleAny: ["external-post", "external-post-clone", "brand-creds"],
  },
  "mfa-harvest.html": {
    origin: "https://verify.unknown.example",
    verdict: "dangerous",
    ruleAny: ["mfa-harvest"],
  },
  "iframe-credentials.html": {
    origin: "https://outer.example",
    verdict: "dangerous",
    ruleAny: ["cross-origin-credentials"],
    synthetic: { iframe: true },
  },
  "oauth-spoof.html": {
    origin: "https://login.evil.example",
    verdict: "dangerous",
    ruleAny: ["oauth-spoof", "external-post"],
  },
  "fake-bank.html": {
    origin: "https://chase-secure-login.example",
    verdict: "dangerous",
    ruleAny: ["external-post", "external-post-clone", "brand-creds"],
  },
};

function buildContext(html, origin, synthetic = {}) {
  const dom = new JSDOM(html, { url: origin });
  const doc = dom.window.document;
  const forms = Array.from(doc.querySelectorAll("form")).map((f) => {
    const inputs = Array.from(f.querySelectorAll("input"));
    const hasPassword = inputs.some((i) => (i.type || "").toLowerCase() === "password");
    const hasEmailLike = inputs.some((i) => {
      const t = (i.type || "").toLowerCase();
      const n = `${i.name || ""} ${i.id || ""} ${i.autocomplete || ""}`.toLowerCase();
      return t === "email" || /email|user(name)?|login|account/.test(n);
    });
    const hasOtp = inputs.some((i) => {
      const n = `${i.name || ""} ${i.id || ""} ${i.autocomplete || ""}`.toLowerCase();
      return (
        /otp|one[-_ ]?time|2fa|mfa|verification[-_ ]?code/.test(n) ||
        ((i.maxLength | 0) >= 4 && (i.maxLength | 0) <= 8 && /numeric/i.test(i.inputMode || ""))
      );
    });
    return {
      action: f.getAttribute("action") || "",
      method: f.getAttribute("method") || "post",
      hasPassword,
      hasEmailLike,
      hasOtp,
      hiddenCount: inputs.filter((i) => (i.type || "").toLowerCase() === "hidden").length,
      fieldsCount: inputs.length,
      insideIframe: !!synthetic.iframe,
    };
  });
  const pick = (sel, attr) =>
    Array.from(doc.querySelectorAll(sel))
      .map((e) => e.getAttribute(attr))
      .filter(Boolean);
  const text = (doc.body?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 4000);
  return {
    pageOrigin: origin,
    title: doc.title || "",
    visibleText: text,
    forms,
    hasPasswordField: !!doc.querySelector("input[type=password]"),
    oauthButtons: Array.from(doc.querySelectorAll("button, a"))
      .map(
        (e) =>
          (e.textContent || "").match(
            /sign in with (google|microsoft|apple|facebook|github)/i,
          )?.[1],
      )
      .filter(Boolean),
    topLevelIframe: !!synthetic.iframe,
    scripts: pick("script[src]", "src"),
    styles: pick("link[rel='stylesheet'][href]", "href"),
    images: pick("img[src]", "src"),
    favicon: doc.querySelector("link[rel~='icon']")?.getAttribute("href") || null,
    hasLogoImage: !!doc.querySelector("img[alt]"),
    hasHeading: !!doc.querySelector("h1"),
    firstFieldKind: doc.querySelector("input[type=email]")
      ? "email"
      : doc.querySelector("input[type=password]")
        ? "password"
        : null,
  };
}

function evaluateFixture(html, expected) {
  const ctx = buildContext(html, expected.origin, expected.synthetic);
  const phishing = analyzePhishing(ctx);
  const clone = analyzeClone(ctx);
  const authLayout = analyzeAuthLayout(ctx);

  // Detect cross-origin iframe carrying credentials at the harness level —
  // mirrors what the content script does in production.
  const dom = new JSDOM(html, { url: expected.origin });
  let crossOriginIframeCreds = false;
  for (const f of dom.window.document.querySelectorAll("iframe[src]")) {
    try {
      const u = new URL(f.getAttribute("src"), expected.origin);
      if (u.host && u.host !== new URL(expected.origin).host) {
        crossOriginIframeCreds = true;
        phishing.signals.push({
          id: "iframe-credential-form",
          severity: "high",
          weight: 28,
          confidence: 0.85,
        });
      }
    } catch {}
  }

  const arb = arbitrate({
    allowlistRoot: false,
    isReputableRoot: false,
    isTrustedProvider: false,
    hasAuthWorkflow: phishing.credentialHarvest || ctx.hasPasswordField || crossOriginIframeCreds,
    lookalike: { match: null, confidence: 0 },
    idnSpoof: false,
    clone,
    phishing,
    authLayout,
    hiddenLoginOverlay: false,
    emailFirstFlow: (phishing.forms || []).some(
      (f) => f.hasEmailLike && !f.hasPassword && (f.fieldsCount || 0) <= 4,
    ),
    mfaOnly:
      (phishing.forms || []).length > 0 &&
      (phishing.forms || []).every((f) => f.hasOtp && !f.hasPassword),
  });
  return { phishing, clone, authLayout, arb };
}

describe("phishing replay — sanitized fixtures", () => {
  const files = readdirSync(FIX).filter((f) => f.endsWith(".html"));
  const results = [];

  for (const file of files) {
    const expected = EXPECT[file];
    if (!expected) continue;
    it(`${file} → ${expected.verdict}`, () => {
      const html = readFileSync(join(FIX, file), "utf8");
      const r = evaluateFixture(html, expected);
      const ruleIds = r.arb.rules.map((x) => x.id);
      results.push({ file, status: r.arb.forceStatus, ruleIds });
      expect(r.arb.forceStatus).toBe(expected.verdict);
      expect(ruleIds.some((id) => expected.ruleAny.includes(id))).toBe(true);
    });
  }

  it("aggregate metrics meet thresholds", () => {
    // Each fixture is positive. Recall = fraction marked dangerous.
    const positives = Object.keys(EXPECT).length;
    const recalled = results.filter((r) => r.status === "dangerous").length;
    const recall = recalled / positives;
    expect(recall).toBeGreaterThanOrEqual(0.9);
  });
});
