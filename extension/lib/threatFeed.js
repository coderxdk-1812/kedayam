// Kedayam — freeware threat-intelligence feed (local-first, key-less).
//
// Replaces the dependency on commercial reputation APIs (Google Safe Browsing /
// VirusTotal both require keys) with a free, privacy-preserving model:
//
//   * DEFAULT (offline): match the visited hostname against the bundled
//     BLOCKLIST_SEED — zero network, zero keys, nothing leaves the device.
//   * OPT-IN (refresh):  the user can enable a periodic pull of FREE public
//     blocklists (URLhaus, OpenPhish, Phishing.Database). Only the feed files
//     are downloaded — the user's browsing is never sent anywhere. Matching of
//     the user's actual URL still happens locally against the cached list.
//
// The matcher is a PURE function so it is fully unit-testable without chrome.
// The refresh/storage helpers are thin and dependency-injected (fetch/storage
// passed in) so they can be exercised in tests and stay out of the hot path.

import { rootDomain } from "./lookalike.js";
import { BLOCKLIST_SEED } from "./rules/blocklistSeed.js";

// Free, no-key, public blocklists. Plain-text host/URL lists. Used ONLY when
// the user explicitly enables feed refresh in Options.
export const FREE_FEEDS = Object.freeze([
  {
    id: "urlhaus",
    name: "URLhaus (abuse.ch)",
    kind: "host",
    url: "https://urlhaus.abuse.ch/downloads/text_online/",
  },
  {
    id: "phishing-army",
    name: "Phishing Army Blocklist",
    kind: "host",
    url: "https://phishing.army/download/phishing_army_blocklist.txt",
  },
  {
    id: "openphish",
    name: "OpenPhish Community",
    kind: "url",
    url: "https://openphish.com/feed.txt",
  },
]);

const MAX_FEED_ENTRIES = 200000; // hard cap so a bad feed can't blow up storage

/**
 * Normalize one raw feed line into a bare lowercase hostname, or "" to skip.
 * Handles comment lines, hosts-file format ("0.0.0.0 evil.com"), and full URLs.
 * @param {string} line
 * @returns {string}
 */
export function normalizeFeedHost(line) {
  if (typeof line !== "string") return "";
  let s = line.trim();
  if (!s || s.startsWith("#") || s.startsWith("!")) return "";
  // hosts-file format: strip a leading IP + whitespace.
  s = s.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, "");
  // Full URL → hostname.
  if (/^https?:\/\//i.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      return "";
    }
  } else {
    // Strip any path that slipped through.
    s = s.split("/")[0];
  }
  s = s
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.$/, "");
  // Reject obvious non-hosts.
  if (!s.includes(".") || /\s/.test(s) || s.length > 253) return "";
  return s;
}

/**
 * Build a Set from raw feed text (one entry per line), bounded.
 * @param {string} text
 * @returns {Set<string>}
 */
export function parseFeed(text) {
  const set = new Set();
  if (typeof text !== "string") return set;
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const h = normalizeFeedHost(line);
    if (h) set.add(h);
    if (set.size >= MAX_FEED_ENTRIES) break;
  }
  return set;
}

/**
 * Pure blocklist match. Checks the full host and its eTLD+1 against the bundled
 * seed plus any extra entries (from the opt-in feed cache).
 * @param {string} host
 * @param {Set<string>|string[]|null} [extra]
 * @returns {{ match:boolean, matchedHost:string|null, source:string|null }}
 */
export function matchBlocklist(host, extra = null) {
  const miss = { match: false, matchedHost: null, source: null };
  if (!host || typeof host !== "string") return miss;
  const h = host.toLowerCase().replace(/^www\./, "");
  const root = rootDomain(h);
  const extraSet = extra instanceof Set ? extra : Array.isArray(extra) ? new Set(extra) : null;

  for (const candidate of [h, root]) {
    if (SEED_SET.has(candidate)) {
      return { match: true, matchedHost: candidate, source: "bundled" };
    }
    if (extraSet && extraSet.has(candidate)) {
      return { match: true, matchedHost: candidate, source: "feed" };
    }
  }
  return miss;
}

const SEED_SET = new Set(BLOCKLIST_SEED);

// ---------------------------------------------------------------------------
// Opt-in refresh + storage (background only). Dependency-injected so tests can
// drive them with fakes and the hot path never imports chrome here.
// ---------------------------------------------------------------------------

const FEED_STORAGE_KEY = "kedayam:v1:threatfeed";

/**
 * Refresh the opt-in feed cache. Caller passes a fetch implementation and a
 * storage setter. Returns the number of entries cached. Network failures are
 * swallowed per-feed so one dead mirror never aborts the refresh.
 * @param {(url:string)=>Promise<Response>} fetchImpl
 * @param {(obj:object)=>Promise<void>} storageSet
 * @param {{ feeds?: typeof FREE_FEEDS, now?: number }} [opts]
 */
export async function refreshThreatFeed(fetchImpl, storageSet, opts = {}) {
  const feeds = opts.feeds || FREE_FEEDS;
  const merged = new Set();
  const sources = [];
  for (const feed of feeds) {
    try {
      const res = await fetchImpl(feed.url);
      if (!res || !res.ok) continue;
      const text = await res.text();
      const set = parseFeed(text);
      for (const h of set) {
        merged.add(h);
        if (merged.size >= MAX_FEED_ENTRIES) break;
      }
      sources.push({ id: feed.id, count: set.size });
    } catch {
      /* skip dead feed */
    }
    if (merged.size >= MAX_FEED_ENTRIES) break;
  }
  const payload = {
    entries: Array.from(merged),
    sources,
    updatedAt: opts.now || 0,
  };
  await storageSet({ [FEED_STORAGE_KEY]: payload });
  return payload.entries.length;
}

/**
 * Load the cached feed entries (opt-in). Returns a Set (possibly empty).
 * @param {(keys:string)=>Promise<object>} storageGet
 */
export async function loadStoredBlocklist(storageGet) {
  try {
    const data = await storageGet(FEED_STORAGE_KEY);
    const payload = data && data[FEED_STORAGE_KEY];
    if (payload && Array.isArray(payload.entries)) return new Set(payload.entries);
  } catch {
    /* no cache */
  }
  return new Set();
}

export const _internal = { FEED_STORAGE_KEY, MAX_FEED_ENTRIES, SEED_SET };
