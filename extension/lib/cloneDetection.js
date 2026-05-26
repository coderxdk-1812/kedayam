// Kedayam — clone-website detection.
//
// Phishing kits frequently load assets (CSS, JS, images, favicon) from a
// different origin than the page they're served on — typically the real
// brand's CDN or the attacker's staging server. We score the page on:
//   - cross-origin script/style ratio (excluding trusted CDNs)
//   - favicon served from a different eTLD+1 than the page
//   - <img> sources whose host is a known protected brand while the page
//     itself is *not* that brand (logo theft).
//
// Inputs are collected by the content script (DOM-only) and passed into
// the trust engine via ctx.pageContext.

import { isTrustedCdn } from "./safeBrowsing.js";
import { rootDomain } from "./lookalike.js";
import { analyzeAuthLayout } from "./authLayout.js";

const PROTECTED_BRAND_HOSTS = [
  "paypal.com", "google.com", "gmail.com", "apple.com", "microsoft.com",
  "amazon.com", "facebook.com", "instagram.com", "github.com",
  "ionos.com", "1and1.com", "binance.com", "coinbase.com", "metamask.io", "chase.com",
  "wellsfargo.com", "bankofamerica.com", "hdfcbank.com", "icicibank.com",
];

function hostOf(u) {
  try { return new URL(u, "https://x/").hostname.toLowerCase(); } catch { return ""; }
}

/**
 * @param {{ pageOrigin:string, scripts:string[], styles:string[],
 *           images:string[], favicon?:string }} ctx
 * @returns {{ score:number, confidence:number, reasons:string[],
 *             crossOriginRatio:number, brandImageMismatch:boolean }}
 */
export function analyzeClone(ctx) {
  const reasons = [];
  if (!ctx || !ctx.pageOrigin) return empty();
  let pageRoot;
  try { pageRoot = rootDomain(new URL(ctx.pageOrigin).hostname.replace(/^www\./, "")); }
  catch { return empty(); }

  const assetUrls = [...(ctx.scripts || []), ...(ctx.styles || [])];
  const externalAssets = assetUrls
    .map(hostOf).filter(Boolean)
    .filter((h) => rootDomain(h.replace(/^www\./, "")) !== pageRoot)
    .filter((h) => !isTrustedCdn(h));
  const brandAssets = assetUrls
    .map(hostOf).filter(Boolean)
    .map((h) => rootDomain(h.replace(/^www\./, "")))
    .filter((r) => PROTECTED_BRAND_HOSTS.includes(r) && r !== pageRoot);

  const totalAssets = (ctx.scripts?.length || 0) + (ctx.styles?.length || 0);
  const crossOriginRatio = totalAssets ? externalAssets.length / totalAssets : 0;

  // Favicon hosted off-domain is a strong clone signal.
  let faviconMismatch = false;
  if (ctx.favicon) {
    const fh = hostOf(ctx.favicon);
    if (fh && rootDomain(fh.replace(/^www\./, "")) !== pageRoot && !isTrustedCdn(fh)) {
      faviconMismatch = true;
      reasons.push(`favicon loaded from ${fh}`);
    }
  }

  // Brand-logo theft: an <img> hosted on a known brand's domain while
  // the page itself isn't that brand.
  let brandImageMismatch = false;
  for (const src of (ctx.images || []).slice(0, 50)) {
    const h = hostOf(src);
    if (!h) continue;
    const r = rootDomain(h.replace(/^www\./, ""));
    if (PROTECTED_BRAND_HOSTS.includes(r) && r !== pageRoot) {
      brandImageMismatch = true;
      reasons.push(`uses brand image from ${r}`);
      break;
    }
  }

  if (crossOriginRatio >= 0.5 && externalAssets.length >= 3) {
    reasons.push(`${Math.round(crossOriginRatio * 100)}% of assets load from unrelated origins`);
  }
  if (brandAssets.length) {
    reasons.push(`loads script/style assets associated with ${[...new Set(brandAssets)].join(", ")}`);
  }

  // Compose a 0..1 confidence.
  let confidence = 0;
  if (faviconMismatch) confidence += 0.5;
  if (brandImageMismatch) confidence += 0.5;
  if (brandAssets.length) confidence += 0.45;
  if (crossOriginRatio >= 0.5 && externalAssets.length >= 3) {
    confidence += Math.min(0.4, crossOriginRatio * 0.5);
  }

  // ---- Structural auth-layout corroboration (P4) ----
  // We only ESCALATE a clone verdict when at least one *asset* signal AND
  // one *structural* auth signal agree. Branding alone never produces a
  // dangerous verdict — too noisy in the wild.
  let layout = null;
  try { layout = analyzeAuthLayout(ctx); } catch { layout = null; }
  if (layout && layout.matchedTemplate && layout.matchedRoot) {
    const tplRoot = String(layout.matchedRoot).replace(/^\*/, "").replace(/\*$/, "");
    const wildcard = String(layout.matchedRoot).includes("*");
    const domainMismatch = wildcard
      ? !pageRoot.includes(tplRoot.replace(/\./g, ""))
      : rootDomain(tplRoot.replace(/^www\./, "")) !== pageRoot;
    if (domainMismatch && layout.confidence >= 0.7) {
      // Boost only if corroborated by branding / favicon / asset evidence.
      const corroborated = faviconMismatch || brandImageMismatch ||
        brandAssets.length > 0 || crossOriginRatio >= 0.5;
      if (corroborated) {
        confidence += Math.min(0.35, layout.confidence * 0.4);
        reasons.push(`structurally matches ${layout.matchedTemplate} login on unrelated domain`);
      } else {
        // Surface but do not escalate.
        reasons.push(`layout resembles ${layout.matchedTemplate} login (unverified)`);
      }
    }
  }
  confidence = Math.min(1, confidence);

  // Penalty score (negative contribution magnitude).
  const score = Math.round(50 * confidence);

  return { score, confidence, reasons, crossOriginRatio, brandImageMismatch,
    faviconMismatch, layout };
}

function empty() {
  return { score: 0, confidence: 0, reasons: [], crossOriginRatio: 0,
    brandImageMismatch: false, faviconMismatch: false, layout: null };
}
