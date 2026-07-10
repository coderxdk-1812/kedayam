// Kedayam — protection catalog (single source of truth for in-product transparency).
//
// Powers the "Transparency" panel in Options: for every protection layer it
// states, in plain English, WHAT it does, an HONEST security-uplift rating over a
// stock Chrome + Safe Browsing setup, whether it is currently ON, and — crucially
// — its HONEST LIMIT. Transparency is one of this product's real differentiators,
// so we surface the same candid assessment to users, not just to developers.
//
// Pure/data-only so it is unit-testable and reusable (Options today, popup later).
//
// upliftRating semantics (incremental value ON TOP OF Safe Browsing):
//   HIGH — covers a real gap the baseline largely misses.
//   MED  — a solid supplementary signal / partial overlap with the baseline.
//   LOW  — nice-to-have; mostly redundant or narrow.

/** @typedef {"HIGH"|"MED"|"LOW"} Uplift */

export const PROTECTION_CATALOG = Object.freeze([
  {
    id: "clickfix",
    title: "ClickFix / fake-CAPTCHA guard",
    what: "Blocks pages that copy a system command (PowerShell, mshta, curl|bash) to your clipboard and lure you into running it.",
    upliftRating: "HIGH",
    category: "Malware",
    settingsPath: "detection.clickFixGuard",
    defaultOn: true,
    limit:
      "Best-effort: a determined deferred (on-click) clipboard write may still slip through; lure text is matched mostly in English.",
  },
  {
    id: "data-leak",
    title: "Sensitive-data paste / file guard",
    what: "Warns before you paste or upload a password, API key, card number, or PII into a form or the wrong site.",
    upliftRating: "HIGH",
    category: "Data protection",
    settingsPath: "detection.pasteInterception",
    defaultOn: true,
    limit: "Pattern-based; unusual secret formats or images of secrets are not caught.",
  },
  {
    id: "homoglyph",
    title: "Look-alike & IDN spoof detection",
    what: "Flags hostnames that visually imitate a real brand — homoglyphs, punycode, and mixed-script names like аpple.com.",
    upliftRating: "MED",
    category: "Phishing",
    settingsPath: null, // core engine layer, always on
    defaultOn: true,
    limit: "Catches visual spoofs, not a legitimately-registered brand-adjacent domain.",
  },
  {
    id: "classifier",
    title: "On-device phishing classifier",
    what: "A local model scores page & URL structure, so it can flag a brand-new phishing kit that copies no known brand.",
    upliftRating: "MED",
    category: "Phishing",
    settingsPath: null, // runs in the engine; no per-toggle yet
    defaultOn: true,
    limit:
      "Hand-tuned heuristic — its real-world recall is NOT yet independently measured; treat as corroboration, not proof.",
  },
  {
    id: "url-reputation",
    title: "URL reputation",
    what: "Escalates abused/free TLDs, URL shorteners, brand-in-subdomain, and TLD-swap tricks when a login is present.",
    upliftRating: "MED",
    category: "Phishing",
    settingsPath: "detection.urlReputation",
    defaultOn: true,
    limit: "Signals corroborate; alone they will not block a clean-looking brand-new domain.",
  },
  {
    id: "blocklist",
    title: "Threat blocklist",
    what: "Matches the host against ~12k known phishing/malware hosts baked in offline (no keys, no network).",
    upliftRating: "MED",
    category: "Reputation",
    settingsPath: "detection.localBlocklist",
    defaultOn: true,
    limit:
      "Small vs. commercial cloud feeds (millions); brand-new campaigns need the opt-in feed refresh and go stale otherwise.",
  },
  {
    id: "clone",
    title: "Clone-site detection",
    what: "Cross-checks page assets to spot a cloned login page hosted on the wrong domain.",
    upliftRating: "MED",
    category: "Phishing",
    settingsPath: "detection.cloneDetection",
    defaultOn: true,
    limit: "Needs behavioral corroboration; a bespoke, non-cloned kit may evade it.",
  },
  {
    id: "scareware",
    title: "Tech-support-scam guard",
    what: 'Warns on fake "your PC is infected — call this number" pages (alarmist text + fullscreen lock).',
    upliftRating: "MED",
    category: "Scam",
    settingsPath: "detection.scarewareGuard",
    defaultOn: true,
    limit: "Heuristic on page text/behavior; a subtle scam page may not trip it.",
  },
  {
    id: "download",
    title: "Malicious-download guard",
    what: "Warns before executable downloads (.exe/.msi/.hta…) initiated from low-trust pages.",
    upliftRating: "MED",
    category: "Malware",
    settingsPath: "detection.downloadGuard",
    defaultOn: true,
    limit: "Gated to low-trust pages to avoid nagging; a trusted-looking host is not flagged.",
  },
  {
    id: "permissions",
    title: "Permission monitoring",
    what: "Flags camera / mic / location prompts on low-trust pages.",
    upliftRating: "LOW",
    category: "Privacy",
    settingsPath: "detection.permissionMonitoring",
    defaultOn: true,
    limit: "Awareness only; the browser already prompts for these.",
  },
]);

// Product-wide honest limits (not per-layer). Shown verbatim in the panel.
export const PROTECTION_LIMITS = Object.freeze([
  "This is a defense-in-depth SECOND layer — it complements, and does not replace, Chrome's built-in Safe Browsing.",
  "No cloud reputation by default: brand-new global campaigns may be seen by cloud tools before the local blocklist.",
  "The phishing classifier is a heuristic; its recall is not yet measured on a real labeled corpus.",
  "Strongest value: ClickFix/clipboard attacks, accidental data leaks, and visual (homoglyph/IDN) spoofs.",
]);

function getPath(obj, path) {
  if (!path) return undefined;
  return path.split(".").reduce((a, k) => (a == null ? undefined : a[k]), obj);
}

/**
 * Annotate the catalog with live on/off state resolved from user settings.
 * A layer with no settingsPath is a core engine layer (always on).
 * @param {object|null} settings
 * @returns {Array<object>} catalog entries + { enabled: boolean, core: boolean }
 */
export function getProtectionOverview(settings) {
  return PROTECTION_CATALOG.map((p) => {
    const core = !p.settingsPath;
    let enabled = p.defaultOn;
    if (!core) {
      const v = getPath(settings, p.settingsPath);
      if (typeof v === "boolean") enabled = v;
    } else {
      enabled = true;
    }
    return { ...p, core, enabled };
  });
}

/** Count of currently-active layers and how many rate HIGH uplift. */
export function protectionSummary(settings) {
  const rows = getProtectionOverview(settings);
  return {
    total: rows.length,
    active: rows.filter((r) => r.enabled).length,
    highActive: rows.filter((r) => r.enabled && r.upliftRating === "HIGH").length,
  };
}
