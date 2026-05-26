// Kedayam — performance primitives used by the content script to keep
// page interactions snappy even on dense SPAs. All pure utilities, no
// chrome.* deps so they're trivially unit-testable.

export function debounce(fn, ms = 150) {
  let t = null;
  return (...args) => {
    if (t) clearTimeout(t);
    t = setTimeout(() => { t = null; fn(...args); }, ms);
  };
}

export function throttle(fn, ms = 200) {
  let last = 0, queued = null;
  return (...args) => {
    const now = Date.now();
    if (now - last >= ms) {
      last = now; fn(...args);
    } else if (!queued) {
      const wait = ms - (now - last);
      queued = setTimeout(() => { queued = null; last = Date.now(); fn(...args); }, wait);
    }
  };
}

/**
 * Token-bucket budget — caps how many times an operation can run inside
 * a sliding window. Returns true if the call is allowed, false if it
 * should be dropped. Useful for MutationObserver-driven scans where the
 * worst case is thousands of mutations per second.
 */
export class Budget {
  constructor({ max = 20, windowMs = 1000 } = {}) {
    this.max = max; this.windowMs = windowMs; this.hits = [];
  }
  allow() {
    const cutoff = Date.now() - this.windowMs;
    while (this.hits.length && this.hits[0] < cutoff) this.hits.shift();
    if (this.hits.length >= this.max) return false;
    this.hits.push(Date.now()); return true;
  }
  reset() { this.hits.length = 0; }
}

/** Run on next idle tick, falling back to setTimeout(0) when unavailable. */
export function idle(fn, timeout = 1500) {
  if (typeof globalThis.requestIdleCallback === "function") {
    return globalThis.requestIdleCallback(fn, { timeout });
  }
  return setTimeout(fn, 0);
}
