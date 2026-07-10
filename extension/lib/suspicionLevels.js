// Kedayam — Progressive Suspicion Model (M2).
//
// The arbitration layer used to collapse all evidence into three discrete
// statuses (safe / suspicious / dangerous), which produced harsh, modal
// escalations for soft signals. The progressive model adds two intermediate
// bands so the UX can stay passive for low-confidence anomalies.
//
//   informational  — silent badge tint, no popup nudge
//   contextual     — popup-visible note, no toast, no modal
//   suspicious     — toast, popup banner, no modal block
//   high-risk      — modal-soft (dismissible) + popup banner
//   dangerous      — modal-hard (block-on-input), full popup warning
//
// Mapping is derived from `score`, `forceStatus`, behavioral corroboration,
// and the new trust-anomaly deltas. The function is pure and side-effect
// free — UI layers consume the level via uxPolicy.

export const SUSPICION_LEVELS = Object.freeze({
  informational: 0,
  contextual: 1,
  suspicious: 2,
  highRisk: 3,
  dangerous: 4,
});

const ORDER = ["informational", "contextual", "suspicious", "highRisk", "dangerous"];

/**
 * @param {Object} input
 * @param {number} input.score
 * @param {string} input.status                     — coarse status
 * @param {boolean} [input.behavioralEvidence]
 * @param {number} [input.anomalyDelta]             — points lost to trust decay
 * @param {boolean} [input.trustedRoot]
 * @returns {{level:string, blockingUx:boolean, modal:"none"|"soft"|"hard",
 *            popupBanner:boolean, badgeTint:"green"|"amber"|"red"}}
 */
export function deriveSuspicion(input) {
  const {
    score = 100,
    status = "safe",
    behavioralEvidence = false,
    anomalyDelta = 0,
    trustedRoot = false,
  } = input || {};

  let level = "informational";

  if (status === "dangerous" && behavioralEvidence) level = "dangerous";
  else if (status === "dangerous") level = "highRisk";
  else if (status === "suspicious" && behavioralEvidence) level = "suspicious";
  else if (status === "suspicious") level = "contextual";
  else if (score < 71) level = "contextual";

  // Trusted root anomaly nudges — never modal, only contextual band.
  if (trustedRoot && anomalyDelta >= 5 && level === "informational") {
    level = "contextual";
  }
  if (trustedRoot && level === "highRisk" && !behavioralEvidence) {
    // Don't block on trusted roots without behavioral evidence.
    level = "suspicious";
  }

  const idx = ORDER.indexOf(level);
  const modal = idx >= 4 ? "hard" : idx === 3 ? "soft" : "none";
  return {
    level,
    blockingUx: modal === "hard",
    modal,
    popupBanner: idx >= 2,
    badgeTint: idx >= 3 ? "red" : idx >= 1 ? "amber" : "green",
  };
}

/** Returns true when `a` is at least as severe as `b`. */
export function suspicionAtLeast(a, b) {
  return ORDER.indexOf(a) >= ORDER.indexOf(b);
}
