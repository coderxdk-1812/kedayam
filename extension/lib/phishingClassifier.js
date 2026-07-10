// Kedayam — on-device phishing classifier (bundled, local-only, key-less).
//
// A small logistic-regression model over URL- and DOM-shape features. It runs
// entirely in-page/in-worker: no network, no inference calls, no telemetry —
// the weights ship inside the signed bundle. Unlike the brand-keyword matchers
// (lookalike/urlReputation), this scores the *structure* of a page, so it can
// flag a zero-day kit that impersonates no known brand.
//
// Design goals:
//   * Deterministic & pure → fully unit-testable without chrome.
//   * Explainable → returns the top feature contributions, not a black box.
//   * Low false positives by construction → the model is deliberately weighted
//     to stay calm, the engine only escalates when an auth workflow corroborates,
//     and trusted roots are never flagged (opts.isTrustedRoot short-circuits).
//
// This is a linear model on purpose: it is auditable, ~1KB, needs no runtime
// (no TF.js/ONNX dependency), and cannot execute remote code. It is the
// "bundled, local, no-inference-calls" classifier from the roadmap.

import { rootDomain, toUnicodeHost } from "./lookalike.js";

// Free / high-abuse TLDs (registrable suffix or last label). Kept in sync in
// spirit with urlReputation.js; duplicated small so this module stays standalone.
const ABUSED_TLDS = new Set([
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "work",
  "click",
  "link",
  "xyz",
  "top",
  "online",
  "support",
  "rest",
  "country",
  "kim",
  "science",
  "party",
  "gdn",
  "zip",
  "mov",
]);

// Generic credential-lure path/subdomain tokens (language-neutral English kit
// vocabulary; NOT brand names, so this generalizes across campaigns).
const LURE_TOKENS = [
  "secure",
  "verify",
  "account",
  "login",
  "signin",
  "update",
  "confirm",
  "unlock",
  "billing",
  "recover",
  "wallet",
  "authenticate",
  "validation",
];

// Sigmoid — squashes the linear score into a 0..1 probability.
function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}

// Feature weights + bias. Hand-calibrated (see phishingClassifier.test.js) to
// keep benign, reputable, and ordinary long-tail sites well below the firing
// threshold while still surfacing structurally phishy pages.
const BIAS = -3.2;
const WEIGHTS = Object.freeze({
  notHttps: 1.1,
  punycode: 1.4,
  abusedTld: 1.3,
  manySubdomains: 0.9, // >= 3 labels before the eTLD+1
  hostDigitsRatio: 1.6, // scaled 0..1
  hostHyphens: 0.5, // per hyphen, capped
  hasPasswordField: 1.0,
  crossOriginForm: 1.7, // a login form posting off-origin
  manyExternalScripts: 0.7,
  obfuscation: 1.2, // long base64/hex blobs in page text
  lureTokens: 0.8, // per distinct lure token in host/path, capped
  brandInSubdomain: 1.5, // real-looking brand token buried in a subdomain
});

/**
 * Derive a numeric feature vector from a URL and optional page context.
 * Every field is optional; missing DOM context degrades to URL-only features.
 * @param {string} url
 * @param {object} [pageContext]
 * @returns {Record<string, number>}
 */
export function extractFeatures(url, pageContext = null) {
  const f = {
    notHttps: 0,
    punycode: 0,
    abusedTld: 0,
    manySubdomains: 0,
    hostDigitsRatio: 0,
    hostHyphens: 0,
    hasPasswordField: 0,
    crossOriginForm: 0,
    manyExternalScripts: 0,
    obfuscation: 0,
    lureTokens: 0,
    brandInSubdomain: 0,
  };
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return f;
  }
  const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const unicodeHost = toUnicodeHost(host);
  const root = rootDomain(host);
  const tld = host.split(".").pop();

  f.notHttps = parsed.protocol === "https:" ? 0 : 1;
  f.punycode = /(^|\.)xn--/i.test(host) ? 1 : 0;
  f.abusedTld = ABUSED_TLDS.has(tld) ? 1 : 0;

  const labels = host.split(".");
  const rootLabels = root.split(".").length;
  const subCount = Math.max(0, labels.length - rootLabels);
  f.manySubdomains = subCount >= 3 ? 1 : subCount === 2 ? 0.5 : 0;

  const digits = (host.match(/\d/g) || []).length;
  f.hostDigitsRatio = host.length ? Math.min(1, digits / host.length) : 0;
  f.hostHyphens = Math.min(3, (host.match(/-/g) || []).length);

  const hay = `${unicodeHost}${parsed.pathname}`.toLowerCase();
  const hits = new Set(LURE_TOKENS.filter((t) => hay.includes(t)));
  f.lureTokens = Math.min(3, hits.size);

  // A recognizable brand token sitting in a subdomain (not the eTLD+1) is a
  // classic "paypal.com.evil.tk" tell even without a full homoglyph match.
  const subPart = labels.slice(0, Math.max(0, labels.length - rootLabels)).join(".");
  const BRANDY =
    /\b(paypal|apple|microsoft|google|amazon|netflix|coinbase|metamask|bank|hdfc|icici|sbi|instagram|facebook|whatsapp)\b/;
  f.brandInSubdomain = subPart && BRANDY.test(subPart) ? 1 : 0;

  if (pageContext && typeof pageContext === "object") {
    f.hasPasswordField = pageContext.hasPasswordField ? 1 : 0;
    const forms = Array.isArray(pageContext.forms) ? pageContext.forms : [];
    const origin = pageContext.pageOrigin || parsed.origin;
    f.crossOriginForm = forms.some((frm) => {
      if (!frm || !frm.action) return false;
      try {
        return (
          new URL(frm.action, origin).origin !== origin && (frm.hasPassword || frm.hasEmailLike)
        );
      } catch {
        return false;
      }
    })
      ? 1
      : 0;
    const scripts = Array.isArray(pageContext.scripts) ? pageContext.scripts : [];
    const external = scripts.filter((s) => {
      const src = typeof s === "string" ? s : s?.src;
      if (!src) return false;
      try {
        return new URL(src, origin).origin !== origin;
      } catch {
        return false;
      }
    }).length;
    f.manyExternalScripts = external >= 8 ? 1 : external >= 4 ? 0.5 : 0;
    const text = typeof pageContext.textSample === "string" ? pageContext.textSample : "";
    f.obfuscation =
      /[A-Za-z0-9+/]{120,}={0,2}|(?:%[0-9a-f]{2}){40,}|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){30,}/i.test(
        text,
      )
        ? 1
        : 0;
  }
  return f;
}

/**
 * Classify a URL (+ optional page context) as a phishing risk.
 * @param {string} url
 * @param {object} [opts] { pageContext, isTrustedRoot }
 * @returns {{
 *   probability:number, label:"benign"|"suspicious"|"phishing",
 *   features:Record<string,number>,
 *   topContributors:Array<{feature:string, contribution:number}>,
 *   signals:Array<object>,
 * }}
 */
export function classifyPhishing(url, opts = {}) {
  const features = extractFeatures(url, opts.pageContext || null);

  // Trusted roots never get flagged — the engine already establishes their
  // identity, and this keeps false positives at zero for the sites people
  // actually log into every day.
  if (opts.isTrustedRoot) {
    return { probability: 0, label: "benign", features, topContributors: [], signals: [] };
  }

  let z = BIAS;
  const contributions = [];
  for (const [k, w] of Object.entries(WEIGHTS)) {
    const contribution = w * (features[k] || 0);
    z += contribution;
    if (contribution > 0) contributions.push({ feature: k, contribution: round2(contribution) });
  }
  const probability = round2(sigmoid(z));
  const label = probability >= 0.8 ? "phishing" : probability >= 0.55 ? "suspicious" : "benign";
  const topContributors = contributions.sort((a, b) => b.contribution - a.contribution).slice(0, 4);

  const signals = [];
  if (label !== "benign") {
    const critical = label === "phishing";
    signals.push({
      id: "ml-phishing-structure",
      category: "behavioral",
      severity: critical ? "critical" : "high",
      title: "Page structure matches phishing kits",
      detail:
        `On-device classifier scored this page ${Math.round(probability * 100)}% phishing-like` +
        (topContributors.length
          ? ` (top signals: ${topContributors.map((c) => humanFeature(c.feature)).join(", ")}).`
          : "."),
      // Behavioral evidence — weighted to corroborate, not to dominate. The
      // engine escalates further only when an auth workflow is present.
      weight: critical ? 30 : 18,
      confidence: probability,
    });
  }
  return { probability, label, features, topContributors, signals };
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

function humanFeature(k) {
  return (
    {
      notHttps: "no HTTPS",
      punycode: "punycode host",
      abusedTld: "abused TLD",
      manySubdomains: "deep subdomains",
      hostDigitsRatio: "digit-heavy host",
      hostHyphens: "hyphenated host",
      hasPasswordField: "password field",
      crossOriginForm: "off-origin login form",
      manyExternalScripts: "many external scripts",
      obfuscation: "obfuscated code",
      lureTokens: "credential-lure words",
      brandInSubdomain: "brand hidden in subdomain",
    }[k] || k
  );
}

export const _internal = { WEIGHTS, BIAS, ABUSED_TLDS, LURE_TOKENS, sigmoid };
