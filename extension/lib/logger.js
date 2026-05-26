// Kedayam — leveled, ring-buffered logger. Privacy-first: secrets and
// long opaque tokens are redacted before being kept in the buffer.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MAX_ENTRIES = 200;

export class Logger {
  constructor({ level = "info", scope = "kedayam" } = {}) {
    this.scope = scope;
    this.minLevel = LEVELS[level] ?? LEVELS.info;
    this.entries = [];
  }
  setLevel(level) { this.minLevel = LEVELS[level] ?? this.minLevel; }

  _emit(level, msg, meta) {
    if (LEVELS[level] < this.minLevel) return;
    const entry = {
      level, msg: String(msg).slice(0, 500),
      meta: redact(meta), at: Date.now(), scope: this.scope,
    };
    this.entries.push(entry);
    if (this.entries.length > MAX_ENTRIES) this.entries.shift();
    try {
      const fn = level === "error" ? console.error
              : level === "warn"  ? console.warn
              : level === "debug" ? console.debug : console.info;
      fn(`[${this.scope}]`, msg, meta ?? "");
    } catch {}
    return entry;
  }
  debug(m, meta) { return this._emit("debug", m, meta); }
  info (m, meta) { return this._emit("info",  m, meta); }
  warn (m, meta) { return this._emit("warn",  m, meta); }
  error(m, meta) { return this._emit("error", m, meta); }

  recent(n = 50) { return this.entries.slice(-n); }
  clear() { this.entries.length = 0; }
}

const SECRET_PATTERNS = [
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bghp_[A-Za-z0-9]{36}\b/g,
  /\bxox[abps]-[A-Za-z0-9-]{10,}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
];

export function redact(value) {
  if (value == null) return value;
  if (typeof value === "string") {
    let out = value;
    for (const re of SECRET_PATTERNS) out = out.replace(re, "«redacted»");
    return out.length > 1000 ? out.slice(0, 1000) + "…" : out;
  }
  if (Array.isArray(value)) return value.slice(0, 20).map(redact);
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (/(token|secret|key|password|auth|cookie)/i.test(k)) out[k] = "«redacted»";
      else out[k] = redact(v);
    }
    return out;
  }
  return value;
}
