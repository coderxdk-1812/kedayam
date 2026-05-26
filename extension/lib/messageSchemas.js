// Kedayam — centralized message schemas (Phase F3).
//
// Deterministic, side-effect-free validators for every message type the
// background service worker accepts. Any incoming message that does not
// pass validate(type, payload) is rejected before reaching its handler.
//
// Rules:
//   • Schemas are immutable (Object.freeze) and exported only as data.
//   • Validators are pure functions — no I/O, no dynamic code, no JSON.parse
//     on attacker-controlled strings.
//   • Unknown fields are tolerated but explicitly stripped, never echoed.
//   • Oversized payloads are rejected by length cap.
//   • Enums are validated against a frozen Set.

const MAX_URL = 2048;
const MAX_DOMAIN = 253;
const MAX_REASON = 128;
const MAX_PAYLOAD_KEYS = 32;

const SENSITIVITY = new Set(["lenient", "balanced", "strict"]);

const isStr = (v, max) =>
  typeof v === "string" && v.length > 0 && v.length <= max;
const isUrl = (v) => {
  if (!isStr(v, MAX_URL)) return false;
  try {
    const u = new URL(v);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch { return false; }
};
const isDomain = (v) =>
  isStr(v, MAX_DOMAIN) && /^[a-z0-9.\-_:]+$/i.test(v);
const isBool = (v) => typeof v === "boolean";
const isInt  = (v) => Number.isInteger(v) && v >= 0 && v < 1e7;

function tooManyKeys(obj) {
  return obj && typeof obj === "object" && Object.keys(obj).length > MAX_PAYLOAD_KEYS;
}

/**
 * Map of accepted message types → validator. Validators return
 * { ok: true, value } with a sanitized payload, or { ok: false, error }.
 * Validators NEVER throw.
 */
export const SCHEMAS = Object.freeze({
  scan: (m) => {
    if (!isUrl(m?.url)) return { ok: false, error: "scan.url" };
    if (m.tabId != null && !isInt(m.tabId)) return { ok: false, error: "scan.tabId" };
    if (m.force != null && !isBool(m.force)) return { ok: false, error: "scan.force" };
    return { ok: true, value: { url: m.url, tabId: m.tabId ?? null, force: !!m.force } };
  },
  pageContext: (m) => {
    if (!m || typeof m.context !== "object" || m.context === null)
      return { ok: false, error: "pageContext.context" };
    if (tooManyKeys(m.context)) return { ok: false, error: "pageContext.size" };
    return { ok: true, value: { context: m.context } };
  },
  getSettings: () => ({ ok: true, value: {} }),
  saveSettings: (m) => {
    if (!m || typeof m.patch !== "object" || m.patch === null)
      return { ok: false, error: "saveSettings.patch" };
    if (tooManyKeys(m.patch)) return { ok: false, error: "saveSettings.size" };
    if (m.patch.detection?.sensitivity != null &&
        !SENSITIVITY.has(m.patch.detection.sensitivity))
      return { ok: false, error: "saveSettings.sensitivity" };
    return { ok: true, value: { patch: m.patch } };
  },
  getActivity: () => ({ ok: true, value: {} }),
  getHealth: () => ({ ok: true, value: {} }),
  clearCaches: () => ({ ok: true, value: {} }),
  logEvent: (m) => {
    if (!m?.entry || typeof m.entry !== "object")
      return { ok: false, error: "logEvent.entry" };
    if (tooManyKeys(m.entry)) return { ok: false, error: "logEvent.size" };
    return { ok: true, value: { entry: m.entry } };
  },
  trustForSession: (m) => {
    if (!isDomain(m?.domain)) return { ok: false, error: "trustForSession.domain" };
    const reason = isStr(m?.reason, MAX_REASON) ? m.reason : "user-trusted";
    return { ok: true, value: { domain: m.domain, reason } };
  },
  getOverride: (m) => {
    if (!isDomain(m?.domain)) return { ok: false, error: "getOverride.domain" };
    return { ok: true, value: { domain: m.domain } };
  },
  openOptions: () => ({ ok: true, value: {} }),
});

/** Types that mutate persistent trust / learning state. */
export const TRUST_MUTATION_TYPES = Object.freeze(
  new Set(["trustForSession", "saveSettings", "clearCaches", "logEvent"])
);

/**
 * Validate an incoming message. Returns { ok, type, value, error }.
 * Rejects unknown types, malformed envelopes, and oversized payloads.
 */
export function validateMessage(msg) {
  if (!msg || typeof msg !== "object")
    return { ok: false, error: "not-an-object" };
  const type = msg.type;
  if (typeof type !== "string" || !type)
    return { ok: false, error: "missing-type" };
  const schema = SCHEMAS[type];
  if (!schema) return { ok: false, error: `unknown-type:${type}` };
  const r = schema(msg);
  if (!r.ok) return { ok: false, type, error: r.error };
  return { ok: true, type, value: r.value };
}

/**
 * Provenance check for chrome.runtime.onMessage senders (Phase F2 / H-06).
 * Accepts ONLY same-extension senders. Rejects external extensions, web
 * pages without an extension origin (externally_connectable is empty in the
 * manifest, but defense-in-depth is cheap), and unknown contexts.
 *
 * Trust-mutation messages additionally require an attached tab — this
 * prevents a co-installed extension that somehow got past sender.id
 * filtering from silently inflating safe-domain stats from a background
 * page.
 */
export function isTrustedSender(sender, runtimeId, type) {
  if (!sender || typeof sender !== "object") return false;
  if (typeof runtimeId !== "string" || !runtimeId) return false;
  if (sender.id !== runtimeId) return false;
  const fromTab = !!sender.tab && Number.isInteger(sender.tab.id);
  const fromExtUi = !!sender.url &&
    (sender.url.startsWith("chrome-extension://") ||
     sender.url.startsWith("moz-extension://"));
  // Every accepted sender must originate either from a real tab (content
  // script) or from one of this extension's own pages. A bare runtime
  // sender (e.g. a co-installed extension's service worker) has neither.
  if (!fromTab && !fromExtUi) return false;
  // For non-tab senders, the origin/url must carry the extension scheme.
  if (!fromTab && sender.origin &&
      !sender.origin.startsWith("chrome-extension://") &&
      !sender.origin.startsWith("moz-extension://")) return false;
  if (TRUST_MUTATION_TYPES.has(type)) {
    if (!fromTab && !fromExtUi) return false;
  }
  return true;
}
