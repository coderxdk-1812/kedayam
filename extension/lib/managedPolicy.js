// Kedayam — optional managed-storage policy hook for enterprise admins.
//
// Strict rules:
//   1. Read-only. Kedayam never writes to chrome.storage.managed.
//   2. Schema-validated. Unknown keys ignored, never reflected back.
//   3. No remote URL fetching. Policies arrive via the admin's MDM.
//   4. Settings.json export/import is purely local — no cloud sync.
//
// Supported policy keys:
//   - allowlist:   string[]   additional safe roots
//   - denylist:    string[]   roots to always treat as suspicious
//   - sensitivity: "lenient" | "balanced" | "strict"
//   - debugMode:   boolean    force-disabled in managed contexts? false = user choice

const SENSITIVITY = new Set(["lenient", "balanced", "strict"]);

export function validatePolicy(raw) {
  if (!raw || typeof raw !== "object") return null;
  const out = {};
  if (Array.isArray(raw.allowlist)) {
    out.allowlist = raw.allowlist
      .filter((s) => typeof s === "string" && s.length > 0 && s.length < 256)
      .slice(0, 1000);
  }
  if (Array.isArray(raw.denylist)) {
    out.denylist = raw.denylist
      .filter((s) => typeof s === "string" && s.length > 0 && s.length < 256)
      .slice(0, 1000);
  }
  if (SENSITIVITY.has(raw.sensitivity)) out.sensitivity = raw.sensitivity;
  if (typeof raw.debugMode === "boolean") out.debugMode = raw.debugMode;
  return Object.keys(out).length ? out : null;
}

/** Read managed policy, returning null on any error. Pure-callable in tests. */
export async function readManagedPolicy(storage) {
  try {
    const api =
      storage ||
      (globalThis.chrome && globalThis.chrome.storage && globalThis.chrome.storage.managed);
    if (!api) return null;
    const raw = await new Promise((resolve) => api.get(null, resolve));
    return validatePolicy(raw);
  } catch {
    return null;
  }
}

/**
 * Deterministic export of a user's settings. Strips internal cache,
 * activity log, and any per-host counters that could reveal browsing.
 */
export function exportSettings(settings) {
  if (!settings || typeof settings !== "object") return null;
  const { schemaVersion, detection, allowlist, features } = settings;
  return JSON.parse(
    JSON.stringify({
      schemaVersion: schemaVersion ?? null,
      detection: detection ?? null,
      allowlist: Array.isArray(allowlist) ? allowlist : [],
      features: features ?? null,
      exportedAt: new Date().toISOString(),
    }),
  );
}

/** Reverse of exportSettings; throws never, returns null on bad input. */
export function importSettings(json) {
  if (!json || typeof json !== "object") return null;
  const out = {};
  if (Number.isInteger(json.schemaVersion)) out.schemaVersion = json.schemaVersion;
  if (json.detection && typeof json.detection === "object") out.detection = json.detection;
  if (Array.isArray(json.allowlist))
    out.allowlist = json.allowlist.filter((s) => typeof s === "string");
  if (json.features && typeof json.features === "object") out.features = json.features;
  return out;
}
