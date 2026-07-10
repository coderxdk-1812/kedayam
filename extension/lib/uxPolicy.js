// Kedayam — UX trust policy.
//
// Centralizes warning frequency, cooldowns, and dismissal rules so a single
// place governs how loud the extension is. The product fails when users stop
// trusting alerts; rare, decisive warnings beat frequent noisy ones.

export const UX_POLICY = Object.freeze({
  // A warning for the same { host, kind } pair is suppressed for this long
  // after being shown or dismissed. Prevents alert loops on SPA navigations.
  WARNING_COOLDOWN_MS: 30 * 60 * 1000, // 30 minutes
  // Soft toasts (non-blocking) are even cheaper to repeat, but we still
  // cap to avoid notification spam.
  TOAST_COOLDOWN_MS: 5 * 60 * 1000,
  // Maximum hosts we remember across the session — bounded cache.
  COOLDOWN_MAX_ENTRIES: 256,
  // Confidence required to interrupt the user with a blocking modal.
  // Anything below this becomes a non-blocking toast.
  BLOCKING_CONFIDENCE_MIN: 0.8,
});

/**
 * Bounded LRU-ish cooldown tracker. Pure JS, no chrome.* deps so it
 * unit-tests cleanly in Node.
 */
export class WarningCooldown {
  constructor(policy = UX_POLICY) {
    this.policy = policy;
    /** @type {Map<string, number>} insertion-ordered for LRU eviction */
    this.map = new Map();
  }
  _key(host, kind) {
    return host + "|" + kind;
  }
  _evict() {
    while (this.map.size > this.policy.COOLDOWN_MAX_ENTRIES) {
      const first = this.map.keys().next().value;
      this.map.delete(first);
    }
  }
  /** True if the caller MAY show the warning now. */
  shouldShow(host, kind, kindMs = this.policy.WARNING_COOLDOWN_MS) {
    const k = this._key(host || "_", kind || "_");
    const last = this.map.get(k);
    if (last && Date.now() - last < kindMs) return false;
    return true;
  }
  /** Record that a warning was just shown. */
  markShown(host, kind) {
    const k = this._key(host || "_", kind || "_");
    this.map.delete(k);
    this.map.set(k, Date.now());
    this._evict();
  }
  /** Clear all cooldowns (e.g. on session end). */
  clear() {
    this.map.clear();
  }
  size() {
    return this.map.size;
  }
}

/**
 * Decide how to present a verdict — blocking modal, toast, or silent.
 * Confidence-band gating prevents low-conviction warnings from interrupting.
 */
export function presentationFor(verdict, policy = UX_POLICY) {
  if (!verdict) return "silent";
  const status = verdict.status || verdict.severity;
  const conf = Math.max(verdict.confidence || 0, verdict.phishingConfidence || 0);
  if (status === "dangerous" && conf >= policy.BLOCKING_CONFIDENCE_MIN) return "modal";
  if (status === "dangerous" || status === "suspicious") return "toast";
  if (status === "high" || status === "critical") return "toast";
  return "silent";
}
