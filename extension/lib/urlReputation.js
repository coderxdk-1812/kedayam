// Kedayam — URL reputation heuristics (freeware, fully local, deterministic).
//
// Goes beyond the basic URL-shape checks in trustEngine.js with the patterns
// modern spear-phishing and malware-distribution kits rely on:
//
//   1. Abused / free TLDs        — Freenom (.tk/.ml/.ga/.cf/.gq) + cheap bulk
//                                  TLDs (.zip/.mov/.top/.xyz/.click/…).
//   2. URL shorteners            — bit.ly/t.co/… that hide the real landing.
//   3. Brand-domain-as-subdomain — paypal.com.secure-login.tk, where a real
//                                  brand domain is buried in the subdomain to
//                                  fool users reading left-to-right. HIGH value,
//                                  very low false-positive.
//   4. Phishy host/path tokens   — secure-update, account-verify, webscr, …
//
// Design rules (to keep false positives near zero for normal users):
//   * Every signal is brand-agnostic and returns a structured record matching
//     the trust engine's `fire()` shape (id, category, severity, weight,
//     confidence).
//   * Weak signals (abused TLD, phishy tokens) carry LOW weight and only
//     matter when they corroborate an auth workflow or another signal.
//   * Known reputable / trusted roots are never penalized by this module —
//     the caller passes `isTrustedRoot` and we suppress weak signals.
//   * No network. No storage. Pure function of the URL string.

import { rootDomain } from "./lookalike.js";

// TLDs with documented, disproportionate phishing / malware abuse. Sources:
// Spamhaus "most abused TLDs", Interisle, Freenom free registrations, and the
// 2023 .zip/.mov launch. Kept as a frozen Set for O(1) lookup. This is a
// *soft* signal — a legitimate site can use .xyz — so weight stays low and
// only escalates alongside auth behavior.
export const ABUSED_TLDS = Object.freeze(
  new Set([
    // Freenom free TLDs — historically the #1 phishing source.
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    // 2023 Google TLDs that collide with file extensions.
    "zip",
    "mov",
    // Cheap bulk-registration TLDs repeatedly topping abuse reports.
    "top",
    "xyz",
    "gdn",
    "kim",
    "country",
    "science",
    "work",
    "party",
    "click",
    "link",
    "review",
    "stream",
    "download",
    "loan",
    "racing",
    "win",
    "bid",
    "cricket",
    "men",
    "date",
    "faith",
    "accountant",
    "trade",
    "webcam",
    "rest",
    "fit",
    "cam",
    "sbs",
    "lol",
    "makeup",
    "mom",
    "quest",
    "cyou",
    "icu",
    "monster",
    "beauty",
    "hair",
    "autos",
    "boats",
    "christmas",
    "wang",
    "buzz",
    "rodeo",
    "vip",
    "shop",
  ]),
);

// Common URL-shortening services. A shortener is not malicious by itself, but
// it hides the destination — we surface it so the redirect-chain analysis and
// the user both know the final landing was reached indirectly.
export const URL_SHORTENERS = Object.freeze(
  new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "t.ly",
    "rb.gy",
    "tiny.cc",
    "bl.ink",
    "lnkd.in",
    "db.tt",
    "qr.ae",
    "adf.ly",
    "bit.do",
    "mcaf.ee",
    "su.pr",
    "x.co",
    "v.gd",
    "trib.al",
    "shor.by",
    "soo.gd",
    "clck.ru",
    "tr.im",
    "cli.gs",
    "shrtco.de",
    "1url.com",
    "snip.ly",
  ]),
);

// Brand registrable domains we protect against the "brand-domain-as-subdomain"
// trick. Deliberately a tight, high-traffic list — these are the brands users
// actually get spear-phished as. Matching is on the FULL registrable domain
// (e.g. "paypal.com"), not the bare word, so false positives are negligible.
export const PROTECTED_BRAND_DOMAINS = Object.freeze([
  "paypal.com",
  "apple.com",
  "icloud.com",
  "microsoft.com",
  "microsoftonline.com",
  "office365.com",
  "outlook.com",
  "live.com",
  "google.com",
  "gmail.com",
  "amazon.com",
  "netflix.com",
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
  "linkedin.com",
  "github.com",
  "dropbox.com",
  "adobe.com",
  "coinbase.com",
  "binance.com",
  "metamask.io",
  "chase.com",
  "wellsfargo.com",
  "bankofamerica.com",
  "citi.com",
  "americanexpress.com",
  "hdfcbank.com",
  "icicibank.com",
  "sbi.co.in",
  "axisbank.com",
  "kotak.com",
  "dhl.com",
  "fedex.com",
  "ups.com",
  "usps.com",
  "irs.gov",
  "gov.uk",
]);

// Host / path tokens that recur in credential-harvest and update-lure kits.
// Each is weak on its own; the engine only escalates when an auth workflow is
// also present. Word-ish boundaries keep them from matching inside normal words.
const PHISHY_TOKENS = [
  "secure-",
  "-secure",
  "account-update",
  "verify-account",
  "account-verify",
  "confirm-account",
  "signin-",
  "-signin",
  "login-verify",
  "webscr",
  "update-billing",
  "unlock-account",
  "suspended-account",
  "security-alert",
  "wallet-connect",
  "validate-",
  "recover-account",
  "appeal-",
];

/**
 * @param {string} url
 * @param {{ isTrustedRoot?: boolean, hasAuthWorkflow?: boolean }} [opts]
 * @returns {{
 *   signals: Array<object>,
 *   abusedTld: string|null,
 *   shortener: boolean,
 *   brandSubdomain: { brand: string, host: string }|null,
 *   phishyToken: string|null,
 *   cap: number|null,
 * }}
 */
export function analyzeUrlReputation(url, opts = {}) {
  const out = {
    signals: [],
    abusedTld: null,
    shortener: false,
    brandSubdomain: null,
    tldSwap: null,
    phishyToken: null,
    cap: null,
  };
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return out;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return out;

  const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const root = rootDomain(host);
  const path = (parsed.pathname || "").toLowerCase();
  const isTrusted = !!opts.isTrustedRoot;
  const hasAuth = !!opts.hasAuthWorkflow;

  // --- 1. Brand-domain-as-subdomain (strongest, lowest-FP signal) ---------
  // e.g. paypal.com.account-verify.tk  → host contains "paypal.com" as a label
  // sequence but the *registrable* root is "account-verify.tk".
  for (const brand of PROTECTED_BRAND_DOMAINS) {
    if (root === brand) break; // genuinely on the brand — stop, it's safe.
    // The brand domain must appear as a dotted label sequence followed by a
    // dot (i.e. it's a subdomain segment, not the registrable root).
    if (host.includes(brand + ".") && root !== brand) {
      out.brandSubdomain = { brand, host };
      out.signals.push({
        id: "brand-subdomain-spoof",
        category: "identity",
        severity: "critical",
        title: `Real brand domain hidden in the subdomain`,
        detail: `"${brand}" appears inside ${host}, but the actual site is ${root}. Reading left-to-right makes this look like ${brand}.`,
        weight: 48,
        confidence: 0.9,
      });
      out.cap = out.cap == null ? 25 : Math.min(out.cap, 25);
      break;
    }
  }

  // --- 1b. TLD swap (right brand name, wrong TLD) ------------------------
  // e.g. paypal.co / paypal.org / apple.cm — the second-level label exactly
  // matches a protected brand's, but the registrable domain is not the brand.
  // High-signal and low-FP because the SLD is an *exact* match, not a substring.
  if (!out.brandSubdomain && !isTrusted) {
    const sld = root.includes(".") ? root.slice(0, root.indexOf(".")) : root;
    for (const brand of PROTECTED_BRAND_DOMAINS) {
      if (root === brand) break; // genuine brand — safe.
      const brandSld = brand.slice(0, brand.indexOf("."));
      // Require a distinctive (≥4-char) brand label to avoid ambiguous words.
      if (brandSld.length >= 4 && sld === brandSld && root !== brand) {
        out.tldSwap = { brand, host, root };
        out.signals.push({
          id: "tld-swap",
          category: "identity",
          severity: "high",
          title: `Looks like ${brand} on the wrong domain`,
          detail: `${root} reuses the "${brandSld}" name of ${brand} but is a different registered domain.`,
          weight: 30,
          confidence: 0.8,
        });
        out.cap = out.cap == null ? 45 : Math.min(out.cap, 45);
        break;
      }
    }
  }

  // --- 2. Abused / free TLD ----------------------------------------------
  const tld = host.includes(".") ? host.slice(host.lastIndexOf(".") + 1) : "";
  if (tld && ABUSED_TLDS.has(tld) && !isTrusted) {
    out.abusedTld = tld;
    // Low base weight; higher confidence (and a soft cap) only when the page
    // is also asking for credentials — a free-TLD login page is a classic
    // phishing setup, while a free-TLD blog is harmless.
    const conf = hasAuth ? 0.7 : 0.35;
    out.signals.push({
      id: "abused-tld",
      category: "identity",
      severity: hasAuth ? "medium" : "low",
      title: `High-abuse top-level domain (.${tld})`,
      detail: hasAuth
        ? `.${tld} domains are cheap/free and heavily used for phishing — and this page is requesting sign-in.`
        : `.${tld} is among the most-abused TLDs. Harmless on its own, but treat sign-in or downloads here with caution.`,
      weight: hasAuth ? 14 : 7,
      confidence: conf,
    });
    if (hasAuth && (out.cap == null || out.cap > 60)) out.cap = 60;
  }

  // --- 3. URL shortener ---------------------------------------------------
  if (URL_SHORTENERS.has(root)) {
    out.shortener = true;
    out.signals.push({
      id: "url-shortener",
      category: "behavior",
      severity: "low",
      title: "Link goes through a URL shortener",
      detail: `${root} hides the real destination. Kedayam still evaluates the page you actually land on.`,
      weight: 4,
      confidence: 0.5,
    });
  }

  // --- 4. Phishy host / path tokens (weak, corroborating only) -----------
  if (!isTrusted) {
    const hay = host + " " + path;
    for (const tok of PHISHY_TOKENS) {
      if (hay.includes(tok)) {
        out.phishyToken = tok;
        out.signals.push({
          id: "phishy-token",
          category: "structure",
          severity: hasAuth ? "medium" : "low",
          title: "Suspicious wording in the address",
          detail: `The URL contains "${tok.replace(/-/g, "")}", a phrase common in account-lure phishing.`,
          weight: hasAuth ? 8 : 4,
          confidence: hasAuth ? 0.6 : 0.4,
        });
        break;
      }
    }
  }

  return out;
}

export const _internal = { PHISHY_TOKENS };
