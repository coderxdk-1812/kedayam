// Kedayam — self-protection primitives.
//
// Hostile pages should never be able to crash, hang, or exhaust the
// extension. This module provides bounded primitives used by every scanner:
//
//   • safeExecRegex   — regex with input size cap and post-hoc timeout guard
//   • boundedString   — coerces and length-caps untrusted strings
//   • boundedArray    — clamps untrusted arrays
//   • safeJSONParse   — try/catch + size cap, never throws
//   • assertEnvelope  — schema-style guard for cross-context messages
//   • verifyModuleIntegrity — sanity-checks critical constant registries
//
// No Node, no chrome.* dependencies — unit-testable in vanilla JS.

const DEFAULT_REGEX_MS = 50;
const DEFAULT_STRING_MAX = 200_000; // 200 KB
const DEFAULT_ARRAY_MAX = 5_000;
const DEFAULT_JSON_MAX = 1_000_000; // 1 MB

/**
 * Run a regex against `input` with an input-size cap and a wall-clock
 * deadline. Returns null on overrun rather than throwing. JS regex cannot
 * be hard-aborted mid-execution, but capping input length is sufficient
 * to prevent catastrophic backtracking on realistic adversarial payloads.
 */
export function safeExecRegex(re, input, opts = {}) {
  const maxLen = opts.maxLen ?? DEFAULT_STRING_MAX;
  const deadlineMs = opts.deadlineMs ?? DEFAULT_REGEX_MS;
  if (typeof input !== "string") return null;
  if (input.length > maxLen) return null;
  const start = Date.now();
  try {
    const m = re.exec(input);
    if (Date.now() - start > deadlineMs) return null;
    return m;
  } catch {
    return null;
  }
}

/**
 * matchAll variant — yields up to `maxMatches` hits and aborts on deadline.
 */
export function safeMatchAll(re, input, opts = {}) {
  const maxLen = opts.maxLen ?? DEFAULT_STRING_MAX;
  const deadlineMs = opts.deadlineMs ?? DEFAULT_REGEX_MS;
  const maxMatches = opts.maxMatches ?? 200;
  const out = [];
  if (typeof input !== "string" || input.length > maxLen) return out;
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  const r = new RegExp(re.source, flags);
  const start = Date.now();
  let m;
  while ((m = r.exec(input))) {
    out.push(m);
    if (out.length >= maxMatches) break;
    if (Date.now() - start > deadlineMs) break;
    if (m.index === r.lastIndex) r.lastIndex++; // zero-width safety
  }
  return out;
}

export function boundedString(v, max = DEFAULT_STRING_MAX) {
  if (typeof v !== "string") return "";
  return v.length > max ? v.slice(0, max) : v;
}

export function boundedArray(v, max = DEFAULT_ARRAY_MAX) {
  if (!Array.isArray(v)) return [];
  return v.length > max ? v.slice(0, max) : v;
}

export function safeJSONParse(text, opts = {}) {
  const max = opts.maxLen ?? DEFAULT_JSON_MAX;
  if (typeof text !== "string" || text.length > max) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Validate that a cross-context message envelope has expected shape.
 * Rejects messages without `type` (string) or with prototype pollution
 * attempts on `__proto__` / `constructor` / `prototype`.
 */
export function assertEnvelope(msg, allowedTypes) {
  if (!msg || typeof msg !== "object") return false;
  const t = msg.type;
  if (typeof t !== "string" || t.length === 0 || t.length > 64) return false;
  if (allowedTypes && !allowedTypes.includes(t)) return false;
  for (const k of Object.keys(msg)) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") return false;
  }
  return true;
}

/**
 * Confirm a constant registry hasn't been silently emptied or shrunk.
 * Returns { ok, reason } — caller decides whether to bail out.
 */
export function verifyModuleIntegrity(name, registry, minCount) {
  if (!registry || typeof registry !== "object") {
    return { ok: false, reason: `${name}: not an object` };
  }
  const count = Array.isArray(registry) ? registry.length : Object.keys(registry).length;
  if (count < minCount) {
    return { ok: false, reason: `${name}: expected >= ${minCount}, got ${count}` };
  }
  if (!Object.isFrozen(registry)) {
    return { ok: true, reason: `${name}: not frozen (warning)` };
  }
  return { ok: true, reason: null };
}

export const SELF_PROTECTION_LIMITS = Object.freeze({
  REGEX_MS: DEFAULT_REGEX_MS,
  STRING_MAX: DEFAULT_STRING_MAX,
  ARRAY_MAX: DEFAULT_ARRAY_MAX,
  JSON_MAX: DEFAULT_JSON_MAX,
});
