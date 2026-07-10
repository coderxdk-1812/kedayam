// Kedayam — clone-website detection.
//
// Phishing kits frequently load assets (CSS, JS, images, favicon) from a
// different origin than the page they're served on — typically the real
// brand's CDN or the attacker's staging server. We score the page on:
//   - favicon served from a different eTLD+1 than the page (high-signal)
//   - <img> sources whose host is a known protected brand while the page
//     itself is *not* that brand (logo theft)
//   - structural auth-layout match to a known login template on an
//     unrelated domain
//
// CALIBRATION (clone accuracy stabilisation patch):
//   Asset overlap / cross-origin script-or-style ratio is NEVER counted as
//   a brand-impersonation signal on its own. Shared infrastructure (CDNs,
//   font hosts, analytics) is hard-excluded. Clone confidence only rises
//   when ≥2 independent high-signal indicators agree. Asset ratio is
//   surfaced as informational only.
//
// Inputs are collected by the content script (DOM-only) and passed into
// the trust engine via ctx.pageContext. The function is PURE — it owns
// no module-level state, so every scan is independent and deterministic.

import { isTrustedCdn } from "./safeBrowsing.js";
import { rootDomain } from "./lookalike.js";
import { analyzeAuthLayout } from "./authLayout.js";

const PROTECTED_BRAND_HOSTS = [
  "paypal.com",
  "apple.com",
  "microsoft.com",
  "amazon.com",
  "facebook.com",
  "instagram.com",
  "github.com",
  "ionos.com",
  "1and1.com",
  "binance.com",
  "coinbase.com",
  "metamask.io",
  "chase.com",
  "wellsfargo.com",
  "bankofamerica.com",
  "hdfcbank.com",
  "icicibank.com",
];

// Shared infrastructure. NEVER contributes to clone confidence under any
// condition — including when listed as a "protected brand".
const INFRA_HOSTS = [
  "googleapis.com",
  "gstatic.com",
  "googleusercontent.com",
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  "cloudflare.com",
  "cloudflareinsights.com",
  "cdnjs.cloudflare.com",
  "jsdelivr.net",
  "unpkg.com",
  "bootstrapcdn.com",
  "jquery.com",
  "fontawesome.com",
  "amazonaws.com",
  "cloudfront.net",
  "akamaihd.net",
  "github.io",
  "githubusercontent.com",
  "vercel.app",
  "netlify.app",
  "google-analytics.com",
  "googletagmanager.com",
];

function isInfrastructureHost(host) {
  if (!host) return true;
  const h = String(host)
    .toLowerCase()
    .replace(/^www\./, "");
  if (!h) return true;
  return INFRA_HOSTS.some((c) => h === c || h.endsWith("." + c));
}

function hostOf(u) {
  try {
    const h = new URL(u, "https://x/").hostname.toLowerCase().replace(/^www\./, "");
    return h && h !== "x" ? h : "";
  } catch {
    return "";
  }
}

function safeRoot(host) {
  if (!host) return "";
  try {
    const r = rootDomain(host);
    return r && typeof r === "string" && r.includes(".") ? r.toLowerCase() : "";
  } catch {
    return "";
  }
}

/**
 * @param {{ pageOrigin:string, scripts:string[], styles:string[],
 *           images:string[], favicon?:string }} ctx
 * @returns {{ score:number, confidence:number, reasons:string[],
 *             crossOriginRatio:number, brandImageMismatch:boolean,
 *             faviconMismatch:boolean, signalCount:number, layout:object|null }}
 */
export function analyzeClone(ctx) {
  // Per-scan local state — nothing persists between invocations.
  const reasons = [];
  if (!ctx || !ctx.pageOrigin) return empty();

  let pageHost = "";
  try {
    pageHost = new URL(ctx.pageOrigin).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return empty();
  }
  const pageRoot = safeRoot(pageHost);
  if (!pageRoot) return empty();

  // ---- Asset ratio (informational only — never feeds confidence) ----
  const assetUrls = [
    ...(Array.isArray(ctx.scripts) ? ctx.scripts : []),
    ...(Array.isArray(ctx.styles) ? ctx.styles : []),
  ];
  const externalAssets = assetUrls
    .map(hostOf)
    .filter(Boolean)
    .filter((h) => safeRoot(h) && safeRoot(h) !== pageRoot)
    .filter((h) => !isTrustedCdn(h) && !isInfrastructureHost(h));
  const totalAssets = assetUrls.length;
  const crossOriginRatio = totalAssets ? externalAssets.length / totalAssets : 0;

  // ---- Signal 1: favicon mismatch ----
  let faviconMismatch = false;
  if (ctx.favicon) {
    const fh = hostOf(ctx.favicon);
    const fr = safeRoot(fh);
    if (fr && fr !== pageRoot && !isTrustedCdn(fh) && !isInfrastructureHost(fh)) {
      // Only count when favicon root is itself a known brand — a CDN favicon
      // is not impersonation.
      if (PROTECTED_BRAND_HOSTS.includes(fr)) {
        faviconMismatch = true;
        reasons.push(`favicon loaded from brand domain ${fr}`);
      }
    }
  }

  // ---- Signal 2: brand-logo theft (image hosted on a protected brand) ----
  let brandImageMismatch = false;
  const images = Array.isArray(ctx.images) ? ctx.images.slice(0, 50) : [];
  for (const src of images) {
    const h = hostOf(src);
    if (!h || isInfrastructureHost(h)) continue;
    const r = safeRoot(h);
    if (!r || r === pageRoot) continue;
    if (PROTECTED_BRAND_HOSTS.includes(r)) {
      brandImageMismatch = true;
      reasons.push(`uses brand image from ${r}`);
      break;
    }
  }

  // ---- Signal 3: structural auth-layout match on unrelated domain ----
  let layout = null;
  let layoutSignal = false;
  try {
    layout = analyzeAuthLayout(ctx);
  } catch {
    layout = null;
  }
  if (layout && layout.matchedTemplate && layout.matchedRoot) {
    const tplRoot = String(layout.matchedRoot).replace(/^\*/, "").replace(/\*$/, "");
    const wildcard = String(layout.matchedRoot).includes("*");
    const domainMismatch = wildcard
      ? !pageRoot.includes(tplRoot.replace(/\./g, ""))
      : safeRoot(tplRoot.replace(/^www\./, "")) !== pageRoot;
    if (domainMismatch && layout.confidence >= 0.7) {
      layoutSignal = true;
      reasons.push(`layout resembles ${layout.matchedTemplate} login on unrelated domain`);
    }
  }

  // ---- Signal 4: credential-harvest / external-POST (corroboration from
  // ctx.phishing, supplied by the engine when available) ----
  const ph = ctx.phishing || {};
  const phishingCorroboration =
    !!ph.credentialHarvest || !!ph.externalFormPost || !!ph.oauthSpoof || !!ph.brandImpersonation;
  if (phishingCorroboration) {
    if (ph.externalFormPost) reasons.push("credential form posts off-domain");
    else if (ph.oauthSpoof) reasons.push("OAuth spoof flow detected");
    else if (ph.brandImpersonation) reasons.push("brand impersonation cues in page text");
    else if (ph.credentialHarvest) reasons.push("credential harvest pattern on unknown domain");
  }

  // Asset ratio is reported but NEVER a signal on its own.
  if (crossOriginRatio >= 0.5 && externalAssets.length >= 3) {
    reasons.push(
      `${Math.round(crossOriginRatio * 100)}% of assets load from unrelated non-CDN origins (informational)`,
    );
  }

  // ---- Multi-signal gating ----
  const signals = [faviconMismatch, brandImageMismatch, layoutSignal, phishingCorroboration];
  const signalCount = signals.filter(Boolean).length;

  let confidence = 0;
  if (signalCount >= 2) {
    // Each independent signal contributes ~0.25, capped at 1.
    confidence = Math.min(
      1,
      signalCount * 0.25 + (layoutSignal ? Math.min(0.15, (layout?.confidence || 0) * 0.2) : 0),
    );
  }

  // Cap clone contribution. Clone alone cannot push a site to dangerous —
  // it must be corroborated by a behavioral phishing signal. Without that,
  // contribution stays capped low (informational nudge).
  const corroboratedScore = Math.round(35 * confidence);
  const informationalScore = Math.round(10 * confidence);
  const score = phishingCorroboration ? corroboratedScore : informationalScore;

  return {
    score,
    confidence,
    reasons,
    crossOriginRatio,
    brandImageMismatch,
    faviconMismatch,
    signalCount,
    layout,
  };
}

function empty() {
  return {
    score: 0,
    confidence: 0,
    reasons: [],
    crossOriginRatio: 0,
    brandImageMismatch: false,
    faviconMismatch: false,
    signalCount: 0,
    layout: null,
  };
}
