// Kedayam — centralized feature flags & schema versioning.
//
// One source of truth for behavioral toggles. New releases MUST bump
// SCHEMA_VERSION and provide a migration in `migrate()`. Constants here are
// FROZEN so a hostile script cannot mutate them at runtime.

export const SCHEMA_VERSION = 3;

export const FEATURE_FLAGS = Object.freeze({
  // detection
  phishingHeuristics: true,
  sensitiveDataEngine: true,
  cloneDetection: true,
  authLayoutFingerprint: true,
  // freeware protection layers (local, key-less)
  localBlocklist: true, // bundled offline threat blocklist
  urlReputation: true, // abused TLD / shortener / brand-subdomain
  clickFixGuard: true, // ClickFix / FakeCaptcha clipboard defense
  downloadGuard: true, // executable-download warning on low-trust pages
  scarewareGuard: true, // tech-support-scam / scareware page warning
  threatFeedAutoUpdate: false, // OPT-IN free public feed refresh (network)
  // UX
  cooldownEnabled: true,
  blockingModal: true,
  reducedMotion: false, // auto-detected at runtime, can be forced
  // diagnostics — OFF by default, no network ever
  debugMode: false,
  inMemoryTrace: false,
  // network
  remoteSafeBrowsing: true, // user-provided API key, else inert
  remoteVirusTotal: false, // off by default; opt-in via key
});

/**
 * Deterministic migration. Pure function — no chrome.* deps.
 * Always returns a settings object stamped with current SCHEMA_VERSION.
 */
export function migrate(stored) {
  const s = stored && typeof stored === "object" ? { ...stored } : {};
  const from = Number.isInteger(s.schemaVersion) ? s.schemaVersion : 1;
  if (from < 2) {
    s.detection = s.detection || { sensitivity: "balanced" };
    s.allowlist = Array.isArray(s.allowlist) ? s.allowlist : [];
  }
  if (from < 3) {
    s.features = { ...FEATURE_FLAGS, ...(s.features || {}) };
    s.diagnostics = s.diagnostics || { debugMode: false };
  }
  s.schemaVersion = SCHEMA_VERSION;
  return s;
}

export function isEnabled(flagName, overrides = {}) {
  if (Object.prototype.hasOwnProperty.call(overrides, flagName)) {
    return !!overrides[flagName];
  }
  return !!FEATURE_FLAGS[flagName];
}
