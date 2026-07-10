// Kedayam — typed message bus.
//
// Wraps chrome.runtime messaging in a versioned envelope so older content
// scripts left over after an extension update are recognised and ignored
// instead of crashing the handler. Also dedupes messages by nonce (handy
// when SPA navigation triggers two near-simultaneous scan requests).

export const ENVELOPE_VERSION = 1;

export function makeEnvelope(type, payload = {}, nonce = cryptoNonce()) {
  return { v: ENVELOPE_VERSION, type, payload, nonce, ts: Date.now() };
}

export function isValidEnvelope(msg) {
  if (!msg || typeof msg !== "object") return false;
  if (msg.v !== ENVELOPE_VERSION) return false;
  if (typeof msg.type !== "string" || !msg.type) return false;
  if (typeof msg.nonce !== "string") return false;
  return true;
}

export function cryptoNonce() {
  // crypto.randomUUID is available in MV3 service workers and DOM.
  try {
    return crypto.randomUUID();
  } catch {
    /* fallthrough */
  }
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

/** Bounded LRU of recently-seen nonces, used to drop duplicates. */
export class NonceCache {
  constructor(max = 256) {
    this.max = max;
    this.set = new Set();
    this.q = [];
  }
  seen(nonce) {
    if (!nonce) return false;
    if (this.set.has(nonce)) return true;
    this.set.add(nonce);
    this.q.push(nonce);
    if (this.q.length > this.max) this.set.delete(this.q.shift());
    return false;
  }
}
