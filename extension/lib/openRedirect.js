// Kedayam — open-redirect / URL-parameter laundering detection (local, pure).
//
// Phishers love riding a trusted domain's reputation: they send a link like
//   https://trusted.com/out?url=https://evil.tld/login
// so the visible host is "trusted.com", but the trusted page immediately
// bounces the victim to the attacker. The redirect-chain analysis catches the
// landing *after* the bounce; this catches the *intent* in the URL itself, so
// we can warn even before the redirect fires (and even if it's a client-side
// bounce the network layer never sees).
//
// Conservative by design: redirect parameters are legitimately used by OAuth /
// SSO / analytics, so an external target alone is only a soft signal. It
// escalates when the target host differs from the page host AND the target
// looks risky (IP literal, embedded credentials, or a percent/double-encoded
// absolute URL trying to hide itself).

import { rootDomain } from "./lookalike.js";

// Query-parameter names commonly used to carry a redirect destination.
const REDIRECT_PARAMS = new Set([
  "url",
  "redirect",
  "redirect_uri",
  "redirecturl",
  "redirect_url",
  "next",
  "return",
  "returnurl",
  "return_url",
  "returnto",
  "dest",
  "destination",
  "continue",
  "goto",
  "target",
  "u",
  "r",
  "link",
  "out",
  "redir",
  "forward",
  "to",
  "rurl",
  "checkout_url",
]);

function decodeMaybe(value) {
  let v = String(value || "");
  for (let i = 0; i < 2; i++) {
    if (!/%[0-9a-f]{2}/i.test(v)) break;
    try {
      v = decodeURIComponent(v);
    } catch {
      break;
    }
  }
  return v;
}

// Extract a target hostname from a parameter value that may be an absolute URL,
// a protocol-relative URL ("//evil.tld/x"), or a percent-encoded one.
function targetHostOf(rawValue, pageOrigin) {
  const v = decodeMaybe(rawValue).trim();
  if (!v) return null;
  let candidate = v;
  if (candidate.startsWith("//")) candidate = "https:" + candidate;
  if (!/^https?:\/\//i.test(candidate)) {
    // Not an absolute external URL (relative path) — not an open redirect.
    if (!/^https?:/i.test(candidate)) return null;
  }
  try {
    const u = new URL(candidate, pageOrigin || "https://x/");
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return {
      host: u.hostname.toLowerCase().replace(/^www\./, ""),
      userinfo: !!(u.username || u.password),
    };
  } catch {
    return null;
  }
}

/**
 * @param {string} url
 * @returns {{
 *   external: boolean,
 *   paramName: string|null,
 *   targetHost: string|null,
 *   signals: Array<object>,
 * }}
 */
export function analyzeOpenRedirect(url) {
  const out = { external: false, paramName: null, targetHost: null, signals: [] };
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return out;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return out;

  const pageRoot = rootDomain(parsed.hostname.toLowerCase().replace(/^www\./, ""));

  for (const [name, value] of parsed.searchParams) {
    if (!REDIRECT_PARAMS.has(name.toLowerCase())) continue;
    const t = targetHostOf(value, parsed.origin);
    if (!t || !t.host) continue;
    const targetRoot = rootDomain(t.host);
    if (targetRoot === pageRoot) continue; // same-site redirect — fine.

    out.external = true;
    out.paramName = name;
    out.targetHost = t.host;

    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(t.host);
    // searchParams decodes values, so read the RAW query to tell whether the
    // destination was percent-encoded to hide it.
    const rawMatch = parsed.search.match(
      new RegExp("[?&]" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^&#]*)", "i"),
    );
    const wasEncoded = /%[0-9a-f]{2}/i.test(rawMatch ? rawMatch[1] : "");
    const risky = isIp || t.userinfo || wasEncoded;

    out.signals.push({
      id: "open-redirect",
      category: "behavior",
      severity: risky ? "high" : "medium",
      title: "Link redirects to a different website",
      detail: `${parsed.hostname} carries a "${name}" parameter that sends you to ${t.host}${
        wasEncoded ? " (the destination was URL-encoded to hide it)" : ""
      }${isIp ? " (a raw IP address)" : ""}.`,
      weight: risky ? 22 : 12,
      confidence: risky ? 0.8 : 0.55,
    });
    break;
  }

  return out;
}

export const _internal = { REDIRECT_PARAMS, decodeMaybe, targetHostOf };
