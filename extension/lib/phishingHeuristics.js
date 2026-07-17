// Kedayam — phishing & credential-harvest heuristics.
//
// Pure function. Inputs come from the content script (DOM-only, no contents
// — only structural facts: form actions, field types, visible brand keywords,
// OAuth-button tells). Output is a set of weighted signals plus an
// arbitration verdict so the trust engine can cap the score for obvious
// credential-collection pages even when no blacklist has flagged them.

import { lookalikeAnalysis, rootDomain } from "./lookalike.js";

// Domains that legitimately serve sign-in flows. A password field here is
// expected, so we don't escalate. Any other domain hosting a password field
// is treated as an "unknown login page" and capped.
const TRUSTED_LOGIN_PROVIDERS = new Set([
  // Google
  "google.com",
  "accounts.google.com",
  "youtube.com",
  "gmail.com",
  // Microsoft
  "microsoft.com",
  "microsoftonline.com",
  "live.com",
  "office.com",
  "outlook.com",
  "office365.com",
  "sharepoint.com",
  // Apple
  "apple.com",
  "icloud.com",
  "appleid.apple.com",
  // Major SaaS / dev
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "atlassian.com",
  "slack.com",
  "dropbox.com",
  "notion.so",
  "figma.com",
  "zoom.us",
  "okta.com",
  "auth0.com",
  "onelogin.com",
  "duosecurity.com",
  "linkedin.com",
  "twitter.com",
  "x.com",
  "facebook.com",
  "instagram.com",
  // Commerce / payments
  "amazon.com",
  "paypal.com",
  "stripe.com",
  "shopify.com",
  "ebay.com",
  "netflix.com",
  "spotify.com",
  "adobe.com",
  // Major banks (sample)
  "chase.com",
  "wellsfargo.com",
  "bankofamerica.com",
  "citi.com",
  "capitalone.com",
  "americanexpress.com",
  "hdfcbank.com",
  "icicibank.com",
  "axisbank.com",
  "kotak.com",
  "sbi.co.in",
  "rbi.org.in",
  "ionos.com",
  "1and1.com",
]);

// Brand-keyword → canonical root. Used to detect impersonation in titles,
// headings, and visible body text. Keep it tight to limit false positives.
const BRAND_KEYWORDS = [
  {
    kw: ["microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint"],
    root: "microsoft.com",
    aliases: [
      "microsoft.com",
      "microsoftonline.com",
      "live.com",
      "office.com",
      "office365.com",
      "outlook.com",
      "sharepoint.com",
    ],
  },
  {
    kw: ["google account", "gmail", "google workspace", "google sign"],
    root: "google.com",
    aliases: [
      "google.com",
      "gmail.com",
      "googlemail.com",
      "googleusercontent.com",
      "googleapis.com",
    ],
  },
  {
    kw: ["apple id", "icloud", "appleid"],
    root: "apple.com",
    aliases: ["apple.com", "icloud.com"],
  },
  { kw: ["paypal"], root: "paypal.com", aliases: ["paypal.com"] },
  {
    kw: ["ionos", "1&1", "webmail ionos", "ionos login"],
    root: "ionos.com",
    aliases: ["ionos.com", "1and1.com"],
  },
  {
    kw: ["facebook", "meta business"],
    root: "facebook.com",
    aliases: ["facebook.com", "fb.com", "meta.com"],
  },
  { kw: ["instagram"], root: "instagram.com", aliases: ["instagram.com"] },
  { kw: ["netflix"], root: "netflix.com", aliases: ["netflix.com"] },
  {
    kw: ["amazon"],
    root: "amazon.com",
    aliases: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"],
  },
  { kw: ["coinbase"], root: "coinbase.com", aliases: ["coinbase.com"] },
  { kw: ["binance"], root: "binance.com", aliases: ["binance.com", "binance.us"] },
  { kw: ["metamask"], root: "metamask.io", aliases: ["metamask.io"] },
  { kw: ["chase bank", "jpmorgan"], root: "chase.com", aliases: ["chase.com", "jpmorgan.com"] },
  { kw: ["wells fargo"], root: "wellsfargo.com", aliases: ["wellsfargo.com"] },
  {
    kw: ["bank of america"],
    root: "bankofamerica.com",
    aliases: ["bankofamerica.com", "bofa.com"],
  },
  { kw: ["hdfc bank"], root: "hdfcbank.com", aliases: ["hdfcbank.com"] },
  { kw: ["icici bank"], root: "icicibank.com", aliases: ["icicibank.com"] },
  {
    kw: ["state bank of india", "sbi online"],
    root: "sbi.co.in",
    aliases: ["sbi.co.in", "onlinesbi.com"],
  },
];

const AUTH_PHRASES =
  /\b(sign in|log in|login|signin|verify your (account|identity)|confirm your (account|identity)|account suspended|unusual activity|two[- ]factor|2fa|mfa|one[- ]time (code|password)|otp|authenticator)\b/i;
// Generic enterprise-SSO phrasing common in AiTM / IdP-relay kits that
// carry NO brand keywords (so brand-impersonation never fires).
const ENTERPRISE_SSO_PHRASES =
  /\b(continue to (your )?(organization|organisation|company|tenant|workspace)|device (verification|registration|trust)|approve (this )?sign[- ]?in request|sso (sign|log) ?in|enterprise (sign|log) ?in|use your (work|corporate|organization|company) account|verify it'?s you|complete sign[- ]?in on (another|your) device|your organization requires)\b/i;

function isTrustedLoginHost(host) {
  if (!host) return false;
  const root = rootDomain(host.replace(/^www\./, ""));
  return TRUSTED_LOGIN_PROVIDERS.has(root);
}

function hostOf(u) {
  try {
    return new URL(u, "https://x/").hostname.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * @typedef {Object} FormInfo
 * @property {string} [action]
 * @property {string} [method]
 * @property {boolean} hasPassword
 * @property {boolean} hasEmailLike   // input[type=email] or name~/email|user|login/
 * @property {boolean} hasOtp         // numeric/otp-style field
 * @property {number}  hiddenCount
 * @property {number}  fieldsCount
 * @property {boolean} insideIframe
 */

/**
 * @param {{
 *   pageOrigin: string,
 *   title?: string,
 *   visibleText?: string,    // capped excerpt of visible <h1>/<h2>/<button>/<a>/<label>
 *   forms?: FormInfo[],
 *   hasPasswordField?: boolean,
 *   oauthButtons?: string[], // e.g. ["google","microsoft"]
 *   topLevelIframe?: boolean // page itself is loaded in an iframe (clickjack tell)
 * }} ctx
 */
export function analyzePhishing(ctx = {}) {
  const out = {
    confidence: 0,
    signals: [],
    credentialHarvest: false,
    authRisk: "none", // none | low | medium | high | critical
    brandImpersonation: null, // { brand, evidence }
    externalFormPost: false,
    cap: null, // optional max trust score
    forceStatus: null, // "suspicious" | "dangerous" | null
  };
  if (!ctx || !ctx.pageOrigin) return out;

  let pageHost, pageRoot;
  try {
    pageHost = new URL(ctx.pageOrigin).hostname.toLowerCase();
    pageRoot = rootDomain(pageHost.replace(/^www\./, ""));
  } catch {
    return out;
  }

  const trusted = TRUSTED_LOGIN_PROVIDERS.has(pageRoot);
  const text = `${ctx.title || ""} \n ${ctx.visibleText || ""}`.toLowerCase();
  const lookalike = lookalikeAnalysis(pageHost);
  const hasIdnSpoof = lookalike.match?.kind === "punycode" || /(^|\.)xn--/i.test(pageHost);

  // ---- Brand impersonation (text/title vs domain) ----
  // A brand mention is only impersonation when the page is ALSO trying to
  // collect credentials for that brand. Merely mentioning or linking to a
  // brand — news articles, blogs, forums, review sites, aggregators such as
  // Hacker News, docs — is normal and must NOT penalize the page. Real brand
  // phishing pairs the brand name with an actual credential prompt (password,
  // OTP, or an OAuth button) on a non-brand domain. A bare "login" link in a
  // header is not credential entry and does not qualify.
  const brandCredIntent =
    !!ctx.hasPasswordField ||
    (ctx.forms || []).some((f) => f.hasPassword || f.hasOtp) ||
    !!ctx.oauthButtons?.length;
  let brandHit = null;
  for (const b of BRAND_KEYWORDS) {
    if (b.kw.some((k) => text.includes(k))) {
      const onBrand = b.aliases.some((a) => pageRoot === a || pageHost.endsWith("." + a));
      if (!onBrand) {
        brandHit = b;
        break;
      }
    }
  }
  if (brandHit && brandCredIntent) {
    out.brandImpersonation = {
      brand: brandHit.root,
      evidence: brandHit.kw.find((k) => text.includes(k)) || brandHit.root,
    };
    out.signals.push({
      id: "brand-impersonation",
      category: "identity",
      severity: "high",
      title: `Page mentions ${brandHit.root} but is not on that domain`,
      detail: `Found "${out.brandImpersonation.evidence}" in page text on ${pageRoot}, which is collecting credentials.`,
      weight: 50,
      confidence: 0.85,
    });
  }

  if (lookalike.match) {
    out.signals.push({
      id: "domain-spoofing",
      category: "identity",
      severity: hasIdnSpoof ? "critical" : "high",
      title: hasIdnSpoof
        ? "Punycode / Unicode domain spoofing detected"
        : `Domain resembles ${lookalike.match.brand || "a protected brand"}`,
      detail: lookalike.reasons.join(" "),
      weight: hasIdnSpoof ? 55 : 38,
      confidence: Math.max(0.75, lookalike.confidence || 0),
    });
  }

  // ---- Credential-harvest detection ----
  const forms = ctx.forms || [];
  const loginForms = forms.filter((f) => f.hasPassword || (f.hasEmailLike && f.hasOtp));
  // Email-first / OTP-only forms are also auth-flow forms; we still check
  // their action target for off-domain POST.
  const authFlowForms = forms.filter((f) => f.hasPassword || f.hasEmailLike || f.hasOtp);
  const hasPwd = !!ctx.hasPasswordField || loginForms.length > 0;
  const hasAuthWorkflow =
    hasPwd || loginForms.length > 0 || AUTH_PHRASES.test(text) || !!ctx.oauthButtons?.length;

  if (hasPwd && !trusted) {
    out.credentialHarvest = true;
    out.authRisk = "high";
    out.signals.push({
      id: "credential-form",
      category: "behavior",
      severity: "high",
      title: "Login / credential form on an unverified domain",
      detail: `${pageRoot} is not a known sign-in provider but is collecting a password.`,
      weight: 25,
      confidence: 0.85,
    });
  } else if (hasPwd && trusted) {
    out.authRisk = "low";
    out.signals.push({
      id: "credential-form-trusted",
      category: "behavior",
      severity: "info",
      title: "Login form on a known sign-in provider",
      detail: `${pageRoot} is a recognized identity provider.`,
      weight: 0,
      confidence: 1,
    });
  }

  // A real credential-entry element must be present for this to fire — an
  // OTP/email login form or an OAuth button. Merely matching sign-in TEXT
  // (a "Log in" / "Sign in" link in a site header, ubiquitous on news sites,
  // blogs, and forums) is NOT a credential workflow and must not penalize the
  // page. Password-bearing forms are handled by `credential-form` above.
  const hasAuthFormElement = loginForms.length > 0 || !!ctx.oauthButtons?.length;
  if (hasAuthFormElement && !hasPwd && !trusted) {
    out.authRisk = "medium";
    out.signals.push({
      id: "unknown-auth-workflow",
      category: "behavior",
      severity: "medium",
      title: "Authentication workflow on an unverified domain",
      detail: `${pageRoot} shows sign-in or verification behavior without strong trust evidence.`,
      weight: 18,
      confidence: 0.7,
    });
  }

  // ---- External form action (POST credentials off-domain) ----
  for (const f of authFlowForms) {
    if (!f.action) continue;
    if (/^javascript:/i.test(f.action)) {
      out.signals.push({
        id: "form-javascript",
        category: "behavior",
        severity: "high",
        title: "Auth form submits via inline JavaScript",
        detail: "Real services post credentials to a server endpoint, not a javascript: URL.",
        weight: 30,
        confidence: 0.9,
      });
      continue;
    }
    const ah = hostOf(f.action.startsWith("/") ? ctx.pageOrigin + f.action : f.action);
    if (!ah) continue;
    const ar = rootDomain(ah.replace(/^www\./, ""));
    if (ar && ar !== pageRoot) {
      out.externalFormPost = true;
      out.signals.push({
        id: "external-form-post",
        category: "behavior",
        severity: "critical",
        title: "Auth form would be posted to a different domain",
        detail: `Form on ${pageRoot} submits to ${ar}.`,
        weight: 60,
        confidence: 0.95,
      });
    }
    if (f.method && f.method.toLowerCase() === "get" && (f.hasPassword || f.hasOtp)) {
      out.signals.push({
        id: "form-get",
        category: "behavior",
        severity: "medium",
        title: "Credential form uses GET (secrets in URL)",
        weight: 20,
        confidence: 0.9,
      });
    }
    if ((f.hiddenCount || 0) >= 4 && (f.fieldsCount || 0) <= 8 && !trusted) {
      out.signals.push({
        id: "hidden-login-fields",
        category: "behavior",
        severity: "medium",
        title: "Auth form contains many hidden fields",
        detail: "Phishing kits often hide routing or victim identifiers inside credential forms.",
        weight: 16,
        confidence: 0.65,
      });
    }
    if (f.insideIframe && !trusted && (f.hasPassword || f.hasOtp)) {
      out.signals.push({
        id: "iframe-credential-form",
        category: "behavior",
        severity: "high",
        title: "Credential form is embedded inside an iframe",
        detail: "Embedded login forms can be used for overlays and clickjacking-style phishing.",
        weight: 28,
        confidence: 0.85,
      });
    }
  }
  // Surface authFlowForms on the result so arbitration can detect MFA-only /
  // email-first patterns directly.
  out.forms = authFlowForms;

  // ---- OAuth button impersonation ----
  if (ctx.oauthButtons?.length && !trusted && hasPwd) {
    out.signals.push({
      id: "oauth-impersonation",
      category: "identity",
      severity: "high",
      title: `"Sign in with ${ctx.oauthButtons.join(", ")}" on an unverified domain`,
      detail: "Phishing pages mimic SSO buttons to look credible.",
      weight: 18,
      confidence: 0.7,
    });
  }

  // ---- Auth phrasing ----
  if (AUTH_PHRASES.test(text) && !trusted && hasPwd) {
    out.signals.push({
      id: "auth-phrasing",
      category: "behavior",
      severity: "medium",
      title: "Page uses urgent authentication phrasing",
      detail: "Phrases like 'verify your account' or 'unusual activity' are common in phishing.",
      weight: 12,
      confidence: 0.6,
    });
  }

  // ---- Top-level page in iframe (clickjack / overlay phish) ----
  if (ctx.topLevelIframe && hasPwd) {
    out.signals.push({
      id: "iframe-login",
      category: "behavior",
      severity: "high",
      title: "Login form rendered inside an iframe",
      weight: 25,
      confidence: 0.8,
    });
  }

  // ---- Generic enterprise-SSO / AiTM detection (Issue C-04) ----
  // Real-world AiTM kits stage credential capture WITHOUT brand keywords:
  // generic "continue to your organization" / "device verification" copy,
  // email-first flows, or MFA-approval prompts. We escalate these when on
  // an unknown root that is also showing auth-collection behavior.
  const hasEnterprisePhrasing = ENTERPRISE_SSO_PHRASES.test(text);
  const emailFirst = authFlowForms.some(
    (f) => f.hasEmailLike && !f.hasPassword && (f.fieldsCount || 0) <= 4,
  );
  const mfaOnly = authFlowForms.some((f) => f.hasOtp && !f.hasPassword);
  if (hasEnterprisePhrasing && !trusted && (hasPwd || emailFirst || mfaOnly || hasAuthWorkflow)) {
    out.signals.push({
      id: "generic-enterprise-auth",
      category: "behavior",
      severity: "high",
      title: "Generic enterprise sign-in flow on an unverified domain",
      detail: `${pageRoot} uses corporate SSO / device-trust phrasing without being a known identity provider.`,
      weight: 24,
      confidence: 0.72,
    });
    // Cap below the safe band so the badge becomes visible even when no
    // brand was named. External POST / MFA-only rules can still escalate
    // this further inside the arbitrator.
    if (out.cap == null || out.cap > 55) out.cap = 55;
    if (!out.forceStatus) out.forceStatus = "suspicious";
    if (out.authRisk === "none" || out.authRisk === "low") {
      out.authRisk = "medium";
    }
  }

  let conf = 0;
  for (const s of out.signals) {
    conf += (s.confidence || 0) * Math.min(1, (s.weight || 0) / 30);
  }
  out.confidence = Math.min(1, conf / 2);

  // ---- Arbitration ----
  // Strong rule: an unknown login page that ALSO impersonates a brand or
  // posts credentials off-domain is treated as dangerous. Blacklist absence
  // CANNOT undo this.
  if (out.credentialHarvest && (out.brandImpersonation || out.externalFormPost || hasIdnSpoof)) {
    out.forceStatus = "dangerous";
    out.authRisk = "critical";
    out.cap = 20;
  } else if (out.credentialHarvest) {
    // Unknown login page with no other phishing tells: never auto-safe.
    out.cap = 60;
    if (out.confidence >= 0.5) out.forceStatus = "suspicious";
  } else if (out.brandImpersonation) {
    out.cap = 50;
    out.forceStatus = "suspicious";
  } else if (hasIdnSpoof) {
    out.cap = 45;
    out.forceStatus = "suspicious";
  }

  return out;
}

export const _internal = { TRUSTED_LOGIN_PROVIDERS, BRAND_KEYWORDS, isTrustedLoginHost };
