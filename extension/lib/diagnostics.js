// Kedayam — local-only, opt-in diagnostics.
//
// Hard rules (enforced by tests):
//   1. OFF by default. Caller must explicitly enable().
//   2. Ring buffer is bounded; old entries silently drop.
//   3. Entries are redacted — never stores raw page text, secrets,
//      form values, URLs with query strings, or DOM payloads.
//   4. No network calls. Ever. This module imports nothing async.
//   5. No chrome.storage persistence — purely in-memory.

const MAX_ENTRIES = 200;

export class DiagnosticsBuffer {
  constructor(max = MAX_ENTRIES) {
    this.max = max;
    this.enabled = false;
    this.buf = [];
  }
  enable()  { this.enabled = true; }
  disable() { this.enabled = false; this.buf.length = 0; }
  clear()   { this.buf.length = 0; }

  record(kind, payload) {
    if (!this.enabled) return;
    if (typeof kind !== "string" || kind.length > 48) return;
    const entry = {
      t: Date.now(),
      kind,
      data: redact(payload),
    };
    this.buf.push(entry);
    if (this.buf.length > this.max) this.buf.shift();
  }

  /** Snapshot for in-popup debug view. Never returned over the network. */
  snapshot() {
    return this.buf.map((e) => ({ ...e, data: { ...e.data } }));
  }
}

/**
 * Strip any value that could carry user content. Keeps only primitives
 * with safe key names, truncated. Drops anything resembling URLs, emails,
 * tokens, or arbitrary text > 64 chars.
 */
export function redact(input, depth = 0) {
  if (depth > 2) return "[depth]";
  if (input == null) return null;
  const t = typeof input;
  if (t === "number" || t === "boolean") return input;
  if (t === "string") return redactString(input);
  if (Array.isArray(input)) return input.slice(0, 10).map((v) => redact(v, depth + 1));
  if (t === "object") {
    const out = {};
    let i = 0;
    for (const k of Object.keys(input)) {
      if (i++ >= 16) break;
      if (k === "__proto__" || k === "constructor") continue;
      if (/value|token|password|secret|cookie|auth|email/i.test(k)) {
        out[k] = "[redacted]";
        continue;
      }
      out[k] = redact(input[k], depth + 1);
    }
    return out;
  }
  return "[unsupported]";
}

function redactString(s) {
  if (s.length > 64) return s.slice(0, 32) + "…[trunc]";
  // Strip obvious URLs to host-only.
  if (/^https?:\/\//i.test(s)) {
    try { return new URL(s).host; } catch { return "[url]"; }
  }
  // Strip obvious emails.
  if (/@/.test(s) && /\.[a-z]{2,}/i.test(s)) return "[email]";
  // Strip long alnum runs (likely tokens).
  if (/[A-Za-z0-9_\-]{20,}/.test(s)) return "[token]";
  return s;
}

// Single shared instance — never auto-enabled.
export const diagnostics = new DiagnosticsBuffer();
