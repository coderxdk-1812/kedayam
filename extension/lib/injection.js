// Kedayam — Injection registry & URL gating.
//
// Owns three responsibilities the declarative content_scripts entry can't:
//   1. A skip-list for origins where injection is impossible or unwanted
//      (chrome://, edge://, devtools://, the Web Store, etc.).
//   2. A per-tab registry that prevents duplicate programmatic injection.
//   3. A best-effort programmatic fallback via chrome.scripting.executeScript
//      for tabs that already existed when the extension installed/updated
//      (declarative content scripts only fire on subsequent navigations).
//
// Pure functions are exported alongside the registry so unit tests can
// exercise the URL gating without a chrome runtime.

const SKIP_PROTOCOLS = new Set([
  "chrome:",
  "edge:",
  "about:",
  "opera:",
  "brave:",
  "vivaldi:",
  "chrome-extension:",
  "moz-extension:",
  "view-source:",
  "devtools:",
  "file:",
  "data:",
  "blob:",
  "javascript:",
]);

const SKIP_HOSTS = [
  "chrome.google.com", // Web Store blocks content scripts
  "chromewebstore.google.com",
  "addons.mozilla.org",
  "microsoftedge.microsoft.com",
];

/** Returns true when Kedayam is allowed to run on the URL. */
export function isInjectableUrl(url) {
  if (!url || typeof url !== "string") return false;
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (SKIP_PROTOCOLS.has(u.protocol)) return false;
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  if (SKIP_HOSTS.some((h) => u.hostname === h || u.hostname.endsWith("." + h))) return false;
  return true;
}

export function reasonForSkip(url) {
  if (!url) return "no-url";
  let u;
  try {
    u = new URL(url);
  } catch {
    return "invalid-url";
  }
  if (SKIP_PROTOCOLS.has(u.protocol)) return `protocol:${u.protocol}`;
  if (u.protocol !== "http:" && u.protocol !== "https:") return `non-web:${u.protocol}`;
  if (SKIP_HOSTS.some((h) => u.hostname === h || u.hostname.endsWith("." + h)))
    return `host:${u.hostname}`;
  return null;
}

/**
 * In-memory registry of tabs Kedayam has injected into. Kept outside any
 * single message handler so service-worker restarts (which clear it) simply
 * lead to one re-injection attempt — which is itself idempotent thanks to
 * the `window.__kedayamLoaded` guard inside content.js.
 */
export class InjectionRegistry {
  constructor() {
    this.tabs = new Map(); /* tabId -> { url, at } */
  }

  has(tabId, url) {
    const e = this.tabs.get(tabId);
    return !!e && e.url === url;
  }
  mark(tabId, url) {
    this.tabs.set(tabId, { url, at: Date.now() });
  }
  clear(tabId) {
    this.tabs.delete(tabId);
  }
  prune(maxAgeMs = 30 * 60 * 1000) {
    const cutoff = Date.now() - maxAgeMs;
    for (const [id, e] of this.tabs) if (e.at < cutoff) this.tabs.delete(id);
  }
  size() {
    return this.tabs.size;
  }
}

/**
 * Best-effort programmatic injection. Safe to call repeatedly; the
 * content script self-guards against double-init and we skip on errors
 * silently (most failures are benign — e.g. tab navigated away).
 */
export async function ensureInjected(tabId, url, registry, scripting = chrome.scripting) {
  if (!isInjectableUrl(url)) return { injected: false, reason: reasonForSkip(url) };
  if (registry.has(tabId, url)) return { injected: false, reason: "already-injected" };
  try {
    await scripting.executeScript({
      target: { tabId, allFrames: false },
      files: ["content/content.js"],
      injectImmediately: true,
      world: "ISOLATED",
    });
    registry.mark(tabId, url);
    return { injected: true };
  } catch (e) {
    return { injected: false, reason: `error:${e?.message || e}` };
  }
}
