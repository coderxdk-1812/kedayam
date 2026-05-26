// Lightweight typed wrappers around chrome.storage with namespacing + TTL.
// All sensitive scanning happens locally — nothing user-typed is ever stored here.

const NS = "kedayam:v1";

export const DEFAULT_SETTINGS = {
  enabled: true,
  detection: {
    sensitivity: "balanced", // strict | balanced | lenient
    regions: { india: true, us: true, eu: true, global: true },
    fileScanning: true,
    pasteInterception: true,
    permissionMonitoring: true,
    redirectAnalysis: true,
    cloneDetection: true,
  },
  privacy: {
    telemetryOptIn: false,
    cacheSafeDomains: true,
  },
  apiKeys: {
    googleSafeBrowsing: "",
    virusTotal: "",
  },
  allowlist: [],
};

export async function getSettings() {
  const { [`${NS}:settings`]: s } = await chrome.storage.local.get(`${NS}:settings`);
  return deepMerge(DEFAULT_SETTINGS, s || {});
}

export async function saveSettings(next) {
  const merged = deepMerge(await getSettings(), next || {});
  await chrome.storage.local.set({ [`${NS}:settings`]: merged });
  return merged;
}

export async function getCache(key) {
  const fullKey = `${NS}:cache:${key}`;
  const { [fullKey]: entry } = await chrome.storage.local.get(fullKey);
  if (!entry) return null;
  if (entry.expiresAt && Date.now() > entry.expiresAt) {
    await chrome.storage.local.remove(fullKey);
    return null;
  }
  return entry.value;
}

export async function setCache(key, value, ttlMs = 60 * 60 * 1000) {
  const fullKey = `${NS}:cache:${key}`;
  await chrome.storage.local.set({
    [fullKey]: { value, expiresAt: Date.now() + ttlMs },
  });
}

// Session-only overrides (cleared when the browser closes).
export async function getSessionOverride(domain) {
  const key = `override:${domain}`;
  const data = await chrome.storage.session.get(key);
  return data[key] || null;
}

export async function setSessionOverride(domain, payload) {
  await chrome.storage.session.set({
    [`override:${domain}`]: { ...payload, at: Date.now() },
  });
}

// Activity log (capped + TTL — privacy hygiene, M-05).
//
// Retention policy:
//   - Hard cap: ACTIVITY_MAX entries (ring buffer).
//   - Soft TTL:  ACTIVITY_TTL_MS — entries older than this are dropped on
//     every append AND on the periodic sweep.
//   - Local-only. No telemetry. No raw page content, clipboard, or
//     credential-derived material is ever stored (callers are responsible
//     for never passing such payloads in; this is enforced by callers and
//     covered by tests/privacy/logRetention.test.js).
export const ACTIVITY_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const ACTIVITY_MAX = 200;

// Field-level allowlist — anything outside this list is stripped before
// persistence so a future caller can never silently leak sensitive data
// into the local activity log.
const ACTIVITY_ALLOWED_FIELDS = new Set([
  "kind", "host", "score", "status", "ruleId", "reason", "severity",
]);

function sanitizeActivityEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return null;
  const out = {};
  for (const k of Object.keys(entry)) {
    if (!ACTIVITY_ALLOWED_FIELDS.has(k)) continue;
    const v = entry[k];
    if (v == null) continue;
    if (typeof v === "string") out[k] = v.slice(0, 256);
    else if (typeof v === "number" && Number.isFinite(v)) out[k] = v;
    else if (typeof v === "boolean") out[k] = v;
  }
  return out;
}

function dropExpired(list, now = Date.now()) {
  if (!Array.isArray(list)) return [];
  const cutoff = now - ACTIVITY_TTL_MS;
  return list.filter((e) => e && typeof e.at === "number" && e.at >= cutoff);
}

export async function appendActivity(entry) {
  const key = `${NS}:activity`;
  const safe = sanitizeActivityEntry(entry);
  if (!safe) return;
  const { [key]: list = [] } = await chrome.storage.local.get(key);
  const pruned = dropExpired(list);
  const next = [{ ...safe, at: Date.now() }, ...pruned].slice(0, ACTIVITY_MAX);
  await chrome.storage.local.set({ [key]: next });
}

export async function getActivity() {
  const key = `${NS}:activity`;
  const { [key]: list = [] } = await chrome.storage.local.get(key);
  const pruned = dropExpired(list);
  // Opportunistically persist the pruned form so cleanup is deterministic
  // even for read-only callers.
  if (pruned.length !== list.length) {
    try { await chrome.storage.local.set({ [key]: pruned }); } catch {}
  }
  return pruned;
}

/** Periodic cleanup hook — call from the background heartbeat. */
export async function sweepExpiredActivity() {
  const key = `${NS}:activity`;
  const { [key]: list = [] } = await chrome.storage.local.get(key);
  const pruned = dropExpired(list);
  if (pruned.length !== list.length) {
    await chrome.storage.local.set({ [key]: pruned });
  }
  return { kept: pruned.length, removed: list.length - pruned.length };
}


export async function clearAllCaches() {
  const all = await chrome.storage.local.get(null);
  const toRemove = Object.keys(all).filter((k) => k.startsWith(`${NS}:cache:`));
  if (toRemove.length) await chrome.storage.local.remove(toRemove);
}

// ---------- Safe-domain learning ----------
// Tracks how often the user has trusted a root domain across sessions.
// After repeated trusts the engine raises the floor for that domain.
export async function getSafeDomainStats() {
  const key = `${NS}:safe-stats`;
  const { [key]: stats = {} } = await chrome.storage.local.get(key);
  return stats;
}

export async function bumpSafeDomain(root, { decay = false } = {}) {
  if (!root) return null;
  const key = `${NS}:safe-stats`;
  const stats = await getSafeDomainStats();
  const cur = stats[root] || { trustCount: 0, lastTrustAt: 0 };
  const next = decay
    ? { ...cur, trustCount: Math.max(0, cur.trustCount - 1) }
    : { trustCount: Math.min(50, cur.trustCount + 1), lastTrustAt: Date.now() };
  stats[root] = next;
  await chrome.storage.local.set({ [key]: stats });
  return next;
}

export async function resetSafeDomain(root) {
  if (!root) return;
  const key = `${NS}:safe-stats`;
  const stats = await getSafeDomainStats();
  delete stats[root];
  await chrome.storage.local.set({ [key]: stats });
}

function deepMerge(base, override) {
  if (Array.isArray(base) || Array.isArray(override)) return override ?? base;
  if (typeof base !== "object" || base === null) return override ?? base;
  const out = { ...base };
  for (const k of Object.keys(override || {})) {
    out[k] = deepMerge(base[k], override[k]);
  }
  return out;
}