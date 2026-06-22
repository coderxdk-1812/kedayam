// Kedayam — Background Service Worker (MV3, ES module)
import { evaluateUrl } from "./lib/trustEngine.js";
import {
  getSettings,
  saveSettings,
  getCache,
  setCache,
  appendActivity,
  getActivity,
  clearAllCaches,
  getSessionOverride,
  setSessionOverride,
  getSafeDomainStats,
  bumpSafeDomain,
  sweepExpiredActivity,
} from "./lib/storage.js";
import { rootDomain } from "./lib/lookalike.js";
import { loadStoredBlocklist, refreshThreatFeed } from "./lib/threatFeed.js";
import { InjectionRegistry, ensureInjected, isInjectableUrl } from "./lib/injection.js";
import { Logger } from "./lib/logger.js";
import { HealthMonitor } from "./lib/health.js";
import { NonceCache, isValidEnvelope } from "./lib/bus.js";
import { validateMessage, isTrustedSender } from "./lib/messageSchemas.js";

const inflight = new Map();
const redirectChains = new Map(); // tabId -> string[]
const lastScanned = new Map(); // tabId -> url (dedupe onCommitted vs onUpdated)
const pageContexts = new Map(); // tabId -> latest pageContext from content
const registry = new InjectionRegistry();
// In-memory cache of the opt-in threat-feed entries (empty unless the user
// enables feed refresh). The bundled seed lives inside the engine itself, so
// reputation works even when this Set is empty.
let blocklistExtra = new Set();
const log = new Logger({ scope: "kedayam.bg", level: "info" });
const health = new HealthMonitor();
const nonces = new NonceCache(512);

chrome.runtime.onInstalled.addListener(async () => {
  await getSettings(); // ensure defaults
  log.info("installed", { version: chrome.runtime.getManifest().version });
  void loadBlocklistCache();
  void maybeRefreshThreatFeed();
  // Re-inject into already-open tabs (declarative script only fires on
  // *future* navigations).
  try {
    const tabs = await chrome.tabs.query({});
    for (const t of tabs) {
      if (t.id && t.url) await ensureInjected(t.id, t.url, registry);
    }
  } catch (e) {
    health.recordError(e, "install:reinject");
  }
});

// Service-worker heartbeat — keeps caches fresh and prunes stale tab state.
chrome.runtime.onStartup?.addListener(() => {
  log.info("startup");
  try {
    chrome.alarms.create("kedayam:heartbeat", { periodInMinutes: 1 });
  } catch {}
  void loadBlocklistCache();
});
try {
  chrome.alarms?.create?.("kedayam:heartbeat", { periodInMinutes: 1 });
} catch {}
// Opt-in threat-feed refresh — every 6h, only acts when the user enabled it.
try {
  chrome.alarms?.create?.("kedayam:feedRefresh", { periodInMinutes: 360 });
} catch {}

// Load the opt-in feed cache from storage into memory (no network).
async function loadBlocklistCache() {
  try {
    blocklistExtra = await loadStoredBlocklist((k) => chrome.storage.local.get(k));
  } catch {
    blocklistExtra = new Set();
  }
}

// Refresh the opt-in feed from FREE public sources — ONLY when the user has
// enabled it in Options. Default install never makes this network call.
async function maybeRefreshThreatFeed(force = false) {
  try {
    const settings = await getSettings();
    if (!force && !settings?.detection?.threatFeedAutoUpdate) return;
    const count = await refreshThreatFeed(
      (url) => fetch(url, { credentials: "omit", cache: "no-store" }),
      (obj) => chrome.storage.local.set(obj),
      { now: Date.now() },
    );
    await loadBlocklistCache();
    log.info("threat feed refreshed", { entries: count });
    return count;
  } catch (e) {
    health.recordError(e, "feedRefresh");
    return 0;
  }
}

chrome.alarms?.onAlarm.addListener((a) => {
  if (a.name === "kedayam:feedRefresh") {
    void maybeRefreshThreatFeed();
    return;
  }
  if (a.name !== "kedayam:heartbeat") return;
  registry.prune();
  // Drop pageContexts for tabs that no longer exist.
  chrome.tabs
    .query({})
    .then((tabs) => {
      const live = new Set(tabs.map((t) => t.id));
      for (const id of pageContexts.keys()) if (!live.has(id)) pageContexts.delete(id);
      for (const id of redirectChains.keys()) if (!live.has(id)) redirectChains.delete(id);
      for (const id of lastScanned.keys()) if (!live.has(id)) lastScanned.delete(id);
    })
    .catch(() => {});
  // M-05 — sweep expired activity log entries on every heartbeat.
  sweepExpiredActivity().catch(() => {});
});

// New top-frame navigation starts a fresh redirect chain.
chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId !== 0) return;
  redirectChains.set(d.tabId, [d.url]);
  pageContexts.delete(d.tabId);
});

// Track redirect chains per tab.
chrome.webRequest.onBeforeRedirect.addListener(
  (d) => {
    if (d.type !== "main_frame") return;
    const list = redirectChains.get(d.tabId) || [];
    list.push(d.url);
    if (list.length > 25) list.shift();
    redirectChains.set(d.tabId, list);
  },
  { urls: ["<all_urls>"] },
);

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || !isInjectableUrl(details.url)) return;
  if (lastScanned.get(details.tabId) === details.url) return;
  lastScanned.set(details.tabId, details.url);
  void scan(details.url, details.tabId, true);
});

chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.status === "loading" && tab.url) {
    // Best-effort programmatic injection for tabs the declarative script missed.
    void ensureInjected(tabId, tab.url, registry);
  }
  if (
    change.status === "complete" &&
    tab.url &&
    isInjectableUrl(tab.url) &&
    lastScanned.get(tabId) !== tab.url
  ) {
    lastScanned.set(tabId, tab.url);
    void scan(tab.url, tabId, false);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  redirectChains.delete(tabId);
  lastScanned.delete(tabId);
  pageContexts.delete(tabId);
  registry.clear(tabId);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      // Provenance gate (Issue H-06): reject anything not originating from
      // this extension. externally_connectable is empty in the manifest so
      // this is defense-in-depth against future config drift or buggy
      // browser builds that leak cross-extension delivery.
      const runtimeId = chrome.runtime.id;
      if (!isTrustedSender(sender, runtimeId, msg?.type)) {
        log.warn("rejected untrusted sender", {
          type: msg?.type,
          sid: sender?.id,
          origin: sender?.origin,
        });
        sendResponse({ ok: false, error: "untrusted-sender" });
        return;
      }
      // Deterministic schema validation (Phase F3).
      const v = validateMessage(msg);
      if (!v.ok) {
        log.warn("rejected message", { type: msg?.type, error: v.error });
        sendResponse({ ok: false, error: `invalid:${v.error}` });
        return;
      }
      // Envelope-style messages get nonce dedupe; flat messages still work.
      if (isValidEnvelope(msg) && nonces.seen(msg.nonce)) {
        sendResponse({ ok: true, deduped: true });
        return;
      }
      health.inc("messages");
      const data = v.value;
      switch (v.type) {
        case "scan":
          sendResponse(
            await scan(data.url, sender.tab?.id ?? data.tabId ?? null, false, data.force),
          );
          break;
        case "pageContext": {
          const tabId = sender.tab?.id;
          if (tabId != null && data.context) {
            pageContexts.set(tabId, data.context);
            const url = sender.tab?.url;
            if (url && isInjectableUrl(url)) {
              // Fault-contained: a malformed/oversized context must not
              // bring down the message handler or prevent the response.
              scan(url, tabId, false, true).catch(() => {});
            }
          }
          sendResponse({ ok: true });
          break;
        }
        case "getSettings":
          sendResponse(await getSettings());
          break;
        case "saveSettings":
          sendResponse(await saveSettings(data.patch));
          break;
        case "getActivity":
          sendResponse(await getActivity());
          break;
        case "getHealth":
          sendResponse({
            ok: true,
            health: health.snapshot(),
            registry: registry.size(),
            recentLogs: log.recent(40),
          });
          break;
        case "clearCaches":
          await clearAllCaches();
          sendResponse({ ok: true });
          break;
        case "logEvent":
          await appendActivity(data.entry);
          sendResponse({ ok: true });
          break;
        case "trustForSession":
          await setSessionOverride(data.domain, { reason: data.reason });
          // Learn from repeated trust. Provenance already validated above;
          // safe-domain learning is therefore reachable ONLY from a tab
          // owned by this extension's content script or its own UI.
          try {
            const r = rootDomain(String(data.domain).replace(/^www\./, ""));
            if (r) await bumpSafeDomain(r);
          } catch {}
          sendResponse({ ok: true });
          break;
        case "getOverride":
          sendResponse(await getSessionOverride(data.domain));
          break;
        case "openOptions":
          chrome.runtime.openOptionsPage();
          sendResponse({ ok: true });
          break;
        case "refreshThreatFeed": {
          const count = await maybeRefreshThreatFeed(true);
          sendResponse({ ok: true, count });
          break;
        }
        default:
          sendResponse({ ok: false, error: "unknown message" });
      }
    } catch (e) {
      health.recordError(e, `message:${msg?.type}`);
      log.error("message handler failed", { type: msg?.type, error: String(e?.message || e) });
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true;
});

// Phase F1: explicitly reject any external connection. externally_connectable
// is also empty in the manifest, but pairing manifest + runtime guards
// removes ambiguity for auditors.
try {
  chrome.runtime.onMessageExternal?.addListener((_msg, _sender, sendResponse) => {
    sendResponse({ ok: false, error: "external-messaging-disabled" });
    return false;
  });
  chrome.runtime.onConnectExternal?.addListener((port) => {
    try {
      port.disconnect();
    } catch {}
  });
} catch {}

function isScannable(url) {
  return isInjectableUrl(url);
}

async function scan(url, tabId, notify, force = false) {
  if (!url || !isInjectableUrl(url)) return null;
  const hasPageContext = tabId != null && pageContexts.has(tabId);
  const cacheKey = `eval:${url}:${hasPageContext ? "dom" : "url"}`;
  if (!force) {
    const cached = await getCache(cacheKey);
    if (cached) {
      maybeBadge(tabId, cached);
      return cached;
    }
    if (inflight.has(cacheKey)) return inflight.get(cacheKey);
  }

  const promise = (async () => {
    health.inc("scans");
    const settings = await getSettings();
    const safeDomainStats = await getSafeDomainStats();
    const pageCtx = hasPageContext ? pageContexts.get(tabId) : null;
    const result = await evaluateUrl(url, {
      settings,
      redirectChain: redirectChains.get(tabId) || [],
      safeDomainStats,
      pageContext: pageCtx,
      authFlow: pageCtx?.authFlow || null,
      blocklistExtra,
    });
    await setCache(cacheKey, result, hasPageContext ? 15 * 60 * 1000 : 2 * 60 * 1000);
    if (result.status !== "safe") {
      await appendActivity({
        kind: "trust",
        host: result.host,
        score: result.score,
        status: result.status,
      });
    }
    maybeBadge(tabId, result);
    if (notify && result.status === "dangerous") {
      try {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon128.png",
          title: "Kedayam — high-risk page",
          message: `${result.host} scored ${result.score}/100. Avoid entering credentials.`,
          priority: 2,
        });
      } catch {}
    }
    if (tabId != null) {
      try {
        chrome.tabs.sendMessage(
          tabId,
          { type: "kedayam:trust", result },
          () => void chrome.runtime.lastError,
        );
      } catch {}
    }
    return result;
  })()
    .catch((err) => {
      // FIND-01 / fail-safe scan pipeline — a rejected scan MUST NOT kill
      // future scans for this tab. We log a redacted diagnostics entry,
      // mark the tab badge as degraded, and let the next navigation /
      // pageContext push trigger a fresh attempt normally.
      health.recordError(err, `scan:${tabId ?? "n/a"}`);
      log.warn("scan failed — entering degraded mode for tab", {
        tabId,
        error: String(err?.message || err).slice(0, 200),
      });
      markBadgeDegraded(tabId);
      return null;
    })
    .finally(() => inflight.delete(cacheKey));

  inflight.set(cacheKey, promise);
  return promise;
}

function maybeBadge(tabId, result) {
  if (tabId == null) return;
  const color =
    result.status === "safe" ? "#10b981" : result.status === "suspicious" ? "#f59e0b" : "#ef4444";
  try {
    chrome.action.setBadgeBackgroundColor({ color, tabId });
    chrome.action.setBadgeText({ text: String(result.score), tabId });
  } catch {}
}

// Fault-contained degraded state — never leaves a stale "all clear" badge
// on a tab whose scan crashed. The next successful scan will overwrite it.
function markBadgeDegraded(tabId) {
  if (tabId == null) return;
  try {
    chrome.action.setBadgeBackgroundColor({ color: "#6b7280", tabId });
    chrome.action.setBadgeText({ text: "…", tabId });
  } catch {}
}
