// Kedayam — Auth-layout fingerprinting.
//
// Phishing kits frequently rebuild a brand's login screen pixel-for-pixel.
// Instead of comparing pixels we compute a *structural* fingerprint of the
// authentication area and compare it against fingerprints of known providers.
//
// A fingerprint is a small ordered tuple — order matters (logo at top, then
// heading, then email field, then password, then OAuth row). Two structurally
// identical login pages on different roots strongly suggest cloning.
//
// Inputs come from the content script as a plain object (no live nodes), so
// this module is testable in Node.

// Known provider templates: distilled structural signatures observed on the
// real sign-in pages. Each entry's `signature` is the canonical ordered tuple
// of "zones" we expect, plus an `oauthRow` flag and `hiddenRatio` band.
export const PROVIDER_TEMPLATES = [
  { id: "microsoft", root: "login.microsoftonline.com",
    signature: ["logo", "heading", "email", "next"],
    oauthRow: false, hiddenRatioBand: [0.3, 0.6],
    keywords: ["sign in", "use your microsoft account", "no account"] },
  { id: "google", root: "accounts.google.com",
    signature: ["logo", "heading", "email", "next"],
    oauthRow: false, hiddenRatioBand: [0.2, 0.55],
    keywords: ["sign in", "use your google account", "forgot email"] },
  { id: "apple", root: "appleid.apple.com",
    signature: ["logo", "heading", "appleid", "next"],
    oauthRow: false, hiddenRatioBand: [0.1, 0.4],
    keywords: ["apple id", "sign in"] },
  { id: "okta", root: "okta.com",
    signature: ["logo", "heading", "email", "password", "submit"],
    oauthRow: true, hiddenRatioBand: [0.2, 0.5],
    keywords: ["sign in", "okta"] },
  { id: "coinbase", root: "coinbase.com",
    signature: ["logo", "heading", "email", "password", "submit"],
    oauthRow: false, hiddenRatioBand: [0.1, 0.4],
    keywords: ["sign in", "coinbase"] },
  { id: "generic-bank", root: "*bank*",
    signature: ["logo", "heading", "username", "password", "submit"],
    oauthRow: false, hiddenRatioBand: [0.0, 0.5],
    keywords: ["online banking", "secure sign on", "account number"] },
];

/**
 * Build a structural fingerprint from a page's DOM facts.
 *
 * @param {{
 *   pageOrigin: string,
 *   title?: string, visibleText?: string,
 *   forms?: Array<{ hasPassword:boolean, hasEmailLike:boolean, hasOtp:boolean,
 *                   hiddenCount:number, fieldsCount:number }>,
 *   oauthButtons?: string[],
 *   hasLogoImage?: boolean, hasHeading?: boolean,
 *   firstFieldKind?: 'email'|'username'|'password'|'otp'|'appleid'|null,
 * }} ctx
 */
export function fingerprintAuthLayout(ctx) {
  const fp = { signature: [], oauthRow: false, hiddenRatio: 0, fieldCount: 0,
    hasPasswordSplit: false };
  if (!ctx) return fp;

  if (ctx.hasLogoImage) fp.signature.push("logo");
  if (ctx.hasHeading) fp.signature.push("heading");

  const loginForm = (ctx.forms || []).find((f) => f.hasPassword || f.hasEmailLike) || null;
  if (loginForm) {
    if (loginForm.hasEmailLike) fp.signature.push(ctx.firstFieldKind || "email");
    if (!loginForm.hasPassword && loginForm.hasEmailLike) {
      fp.signature.push("next"); fp.hasPasswordSplit = true;
    }
    if (loginForm.hasPassword) fp.signature.push("password");
    if (loginForm.hasOtp) fp.signature.push("otp");
    if (loginForm.hasPassword || loginForm.hasOtp) fp.signature.push("submit");

    fp.fieldCount = loginForm.fieldsCount || 0;
    fp.hiddenRatio = loginForm.fieldsCount
      ? loginForm.hiddenCount / loginForm.fieldsCount : 0;
  }
  fp.oauthRow = !!(ctx.oauthButtons && ctx.oauthButtons.length);
  return fp;
}

/**
 * Compare a page fingerprint against the provider templates and return the
 * best match with a 0..1 confidence score.
 *
 * @returns {{ template: typeof PROVIDER_TEMPLATES[number] | null,
 *             confidence: number, reasons: string[] }}
 */
export function matchAuthTemplate(fingerprint, ctx = {}) {
  if (!fingerprint || !fingerprint.signature.length) {
    return { template: null, confidence: 0, reasons: [] };
  }
  const text = (ctx.visibleText || "").toLowerCase() + " " +
    (ctx.title || "").toLowerCase();

  let best = { template: null, confidence: 0, reasons: [] };
  for (const tpl of PROVIDER_TEMPLATES) {
    const reasons = [];
    let score = 0;

    const align = sequenceSimilarity(fingerprint.signature, tpl.signature);
    score += align * 0.55;
    if (align >= 0.8) reasons.push(`layout matches ${tpl.id}`);

    if (tpl.oauthRow === fingerprint.oauthRow) score += 0.1;

    const [lo, hi] = tpl.hiddenRatioBand;
    if (fingerprint.hiddenRatio >= lo && fingerprint.hiddenRatio <= hi) score += 0.1;

    const kwHits = tpl.keywords.filter((k) => text.includes(k)).length;
    if (kwHits) {
      score += Math.min(0.25, kwHits * 0.12);
      reasons.push(`text mentions ${tpl.id} phrases (${kwHits})`);
    }

    if (score > best.confidence) {
      best = { template: tpl, confidence: Math.min(1, score), reasons };
    }
  }
  return best;
}

/**
 * Convenience wrapper: fingerprint + match + verdict.
 * Returns a confidence band the arbitration engine can consume.
 */
export function analyzeAuthLayout(ctx) {
  const fp = fingerprintAuthLayout(ctx);
  const match = matchAuthTemplate(fp, ctx);
  return {
    fingerprint: fp,
    matchedTemplate: match.template?.id || null,
    matchedRoot: match.template?.root || null,
    confidence: round2(match.confidence),
    reasons: match.reasons,
    isLayoutClone: match.confidence >= 0.7 && !!match.template,
  };
}

// Levenshtein-ratio style ordered similarity in [0,1].
function sequenceSimilarity(a, b) {
  if (!a.length && !b.length) return 1;
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = 0; i <= n; i++) dp[i][0] = i;
  for (let j = 0; j <= m; j++) dp[0][j] = j;
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  const maxLen = Math.max(n, m);
  return 1 - dp[n][m] / maxLen;
}
function round2(n) { return Math.round(n * 100) / 100; }
