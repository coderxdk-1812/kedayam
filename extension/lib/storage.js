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

// Activity log (capped, no user content — only metadata).
export async function appendActivity(entry) {
  const key = `${NS}:activity`;
  const { [key]: list = [] } = await chrome.storage.local.get(key);
  const next = [{ ...entry, at: Date.now() }, ...list].slice(0, 200);
  await chrome.storage.local.set({ [key]: next });
}

export async function getActivity() {
  const key = `${NS}:activity`;
  const { [key]: list = [] } = await chrome.storage.local.get(key);
  return list;
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