// Kedayam — tech-support scam / scareware page detection (local, pure).
//
// A huge real-world threat for non-technical users: a page screams "YOUR
// COMPUTER IS INFECTED — call Microsoft support now", often locks the screen
// (fullscreen), spams alert() dialogs, and blocks navigation with beforeunload.
// There is no malware on the page itself — the scam is social engineering to
// get the victim to call a fake "support" number and hand over remote access or
// money. Phishing/URL heuristics miss it because the URL is often a throwaway
// host with no credential form.
//
// This module scores the page's *visible text* plus a few structural runtime
// cues (a tel: link, fullscreen lock, navigation trap) that the content script
// supplies. It is conservative: security blogs and news articles discuss these
// phrases too, so a verdict requires the alarmist phrasing to combine with a
// call-to-action (phone number / "call ... support") or a UI-lock cue.

// Alarmist phrasing buckets. We require evidence from >= 2 distinct buckets,
// or 1 bucket + a structural cue, before warning.
const THREAT_PHRASES = [
  /\byour\s+(computer|pc|system|device|windows)\s+(is|has been|may be)\s+(infected|locked|blocked|compromised|at risk)\b/i,
  /\b(virus(es)?|trojan|spyware|malware)\s+(detected|found|alert)\b/i,
  /\b(security|system)\s+(alert|warning|breach)\b/i,
  /\byour\s+(data|files|identity|information)\s+(is|are|may be)\s+(at risk|stolen|compromised|encrypted)\b/i,
  /\berror\s*(code)?\s*[:#]?\s*[a-z0-9-]{3,}\b/i,
];
const CALL_TO_ACTION = [
  /\bcall\s+(us|now|immediately|microsoft|apple|windows|support|toll[- ]?free)\b/i,
  /\b(toll[- ]?free|helpline|support\s+(line|number|team))\b/i,
  /\bcontact\s+(microsoft|apple|windows)\s+(support|technician)\b/i,
  /\bdo\s+not\s+(close|restart|shut\s*down|turn\s*off|ignore)\b/i,
  /\bcall\s*[:.]?\s*(\+?\d[\d\s().-]{7,}\d)\b/i,
];
// Impersonated vendors used to add legitimacy to the scam.
const FAKE_VENDOR =
  /\b(windows\s+defender|microsoft\s+(security|support)|apple\s+support|norton|mcafee)\b/i;

function countMatches(text, patterns) {
  let n = 0;
  for (const re of patterns) if (re.test(text)) n++;
  return n;
}

/**
 * @param {{
 *   visibleText?: string,
 *   hasTelLink?: boolean,
 *   fullscreen?: boolean,
 *   navTrap?: boolean,      // page installs a beforeunload / blocks leaving
 *   dialogLoop?: boolean,   // repeated alert()/confirm() spam observed
 * }} ctx
 * @returns {{ scam: boolean, confidence: number, reasons: string[] }}
 */
export function classifyScareware(ctx = {}) {
  const out = { scam: false, confidence: 0, reasons: [] };
  const text = String(ctx.visibleText || "").slice(0, 20000);
  if (!text && !ctx.hasTelLink) return out;

  const threatHits = countMatches(text, THREAT_PHRASES);
  const ctaHits = countMatches(text, CALL_TO_ACTION);
  const vendor = FAKE_VENDOR.test(text);
  const structural = [ctx.hasTelLink, ctx.fullscreen, ctx.navTrap, ctx.dialogLoop].filter(
    Boolean,
  ).length;

  if (threatHits) out.reasons.push("alarmist infection/lock messaging");
  if (ctaHits) out.reasons.push("urgent call-a-number instruction");
  if (vendor) out.reasons.push("impersonates a known security vendor");
  if (ctx.fullscreen) out.reasons.push("forced fullscreen lock");
  if (ctx.navTrap) out.reasons.push("blocks you from leaving the page");
  if (ctx.dialogLoop) out.reasons.push("repeated pop-up dialogs");
  if (ctx.hasTelLink) out.reasons.push("prominent phone-number link");

  // Scoring: alarmist text must combine with a call-to-action or a UI-lock cue.
  let score = 0;
  score += Math.min(threatHits, 2) * 0.28;
  score += Math.min(ctaHits, 2) * 0.3;
  score += vendor ? 0.18 : 0;
  score += Math.min(structural, 2) * 0.2;

  // A genuine scam almost always pairs "you're infected" with "call/don't close"
  // or a lock. Text alone (e.g. a security article) must not fire.
  const corroborated =
    (threatHits >= 1 && (ctaHits >= 1 || structural >= 1)) || (ctaHits >= 1 && structural >= 1);

  if (corroborated && score >= 0.6) {
    out.scam = true;
    out.confidence = Math.min(0.97, score);
  }
  return out;
}

export const _internal = { THREAT_PHRASES, CALL_TO_ACTION, FAKE_VENDOR, countMatches };
