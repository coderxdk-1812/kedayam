// Kedayam — Ephemeral Replay Store (Issue NEW-01).
//
// Problem: the original C-03 fix re-read the clipboard via
// navigator.clipboard.readText() at "Continue" time, but the extension
// does NOT hold the "clipboardRead" permission. The call throws
// NotAllowedError, the replay payload becomes empty, and the user is
// stuck in a silent-failure loop.
//
// Solution: capture the original intercepted payload ONCE, hand the
// caller back an opaque token, and zeroize it after the first
// consumption or when its short TTL expires (whichever comes first).
//
// Guarantees:
//   - no permanent storage (in-memory only)
//   - no persistence across page reload (module re-instantiates)
//   - bounded TTL (default 60s)
//   - tokens are single-use; second consume() returns null
//   - explicit zeroize() always wipes payload reference
//   - bounded size; oldest entries evicted when MAX is exceeded
//   - never expose payload through diagnostics / log / serialize APIs

const DEFAULT_TTL_MS = 60 * 1000;
const MAX_ENTRIES = 8;

const _store = new Map(); // token -> { payload, expires, timer }
let _counter = 0;

function _rand() {
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const a = new Uint32Array(2);
    crypto.getRandomValues(a);
    return a[0].toString(36) + a[1].toString(36);
  }
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

function _evictOldest() {
  while (_store.size > MAX_ENTRIES) {
    const first = _store.keys().next().value;
    if (first == null) break;
    zeroize(first);
  }
}

/** Store `payload` and return a single-use token. Empty/non-string payloads are rejected. */
export function storeReplay(payload, ttlMs = DEFAULT_TTL_MS) {
  if (typeof payload !== "string" || !payload.length) return null;
  const token = `kr_${++_counter}_${_rand()}`;
  const entry = { payload, expires: Date.now() + ttlMs, timer: null };
  try {
    entry.timer = setTimeout(() => zeroize(token), ttlMs);
  } catch { /* environments without timers */ }
  _store.set(token, entry);
  _evictOldest();
  return token;
}

/** Consume the token exactly once. Returns the payload string or null. */
export function consumeReplay(token) {
  if (!token) return null;
  const e = _store.get(token);
  if (!e) return null;
  const expired = e.expires < Date.now();
  const value = expired ? null : e.payload;
  // finally-style zeroize on every consume (success OR expiry)
  zeroize(token);
  return value;
}

/** Explicit destruction — safe to call repeatedly. */
export function zeroize(token) {
  const e = _store.get(token);
  if (!e) return;
  try { if (e.timer) clearTimeout(e.timer); } catch {}
  // best-effort string zeroization (V8 will GC; reference clearing is the
  // strongest guarantee a content script can make).
  e.payload = "";
  e.timer = null;
  _store.delete(token);
}

/** Test/diagnostic helpers — never expose payload values. */
export function _size() { return _store.size; }
export function _hasToken(t) { return _store.has(t); }
export function _resetAll() {
  for (const k of Array.from(_store.keys())) zeroize(k);
  _counter = 0;
}
export const EPHEMERAL_REPLAY_DEFAULTS = Object.freeze({
  DEFAULT_TTL_MS, MAX_ENTRIES,
});
