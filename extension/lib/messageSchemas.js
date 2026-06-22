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

const isStr = (v, max) => typeof v === "string" && v.length > 0 && v.length <= max;
const isUrl = (v) => {
  if (!isStr(v, MAX_URL)) return false;
  try {
    const u = new URL(v);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
};
const isDomain = (v) => isStr(v, MAX_DOMAIN) && /^[a-z0-9.\-_:]+$/i.test(v);
const isBool = (v) => typeof v === "boolean";
const isInt = (v) => Number.isInteger(v) && v >= 0 && v < 1e7;

function tooManyKeys(obj) {
  return obj && typeof obj === "object" && Object.keys(obj).length > MAX_PAYLOAD_KEYS;
}

// ----------------------------------------------------------------------
// FIND-01 — strict pageContext schema sanitization.
//
// pageContext is the largest attacker-influenced surface in the extension:
// a hostile or buggy page can deliver any shape over postMessage→content→bg.
// Earlier versions trusted that fields like `forms` were arrays and crashed
// the scan pipeline with `forms.filter is not a function`, silently
// disabling protection for the tab (a per-tab detection DoS).
//
// `sanitizePageContext` is a deterministic, dependency-free, bounded-cost,
// side-effect-free normalizer. Any malformed field is replaced with a safe
// default; downstream consumers can traverse the result without runtime
// guards.
// ----------------------------------------------------------------------

const PCTX_MAX_STR = 8 * 1024;
const PCTX_MAX_SMALL_STR = 2048;
const PCTX_MAX_ARRAY = 256;
const PCTX_MAX_FORMS = 64;
const PCTX_MAX_OAUTH = 16;

const safeStr = (v, max = PCTX_MAX_SMALL_STR) => (typeof v === "string" ? v.slice(0, max) : "");
const safeBool = (v) => v === true;
const safeArr = (v, max = PCTX_MAX_ARRAY) =>
  Array.isArray(v) ? v.filter((x) => x !== undefined).slice(0, max) : [];
const safeStrArr = (v, max = PCTX_MAX_ARRAY, itemMax = PCTX_MAX_SMALL_STR) =>
  safeArr(v, max)
    .filter((x) => typeof x === "string")
    .map((s) => s.slice(0, itemMax));

function safeForm(f) {
  if (!f || typeof f !== "object" || Array.isArray(f)) return null;
  return {
    action: safeStr(f.action, PCTX_MAX_SMALL_STR),
    method: safeStr(f.method, 16),
    hasPassword: safeBool(f.hasPassword),
    hasEmailLike: safeBool(f.hasEmailLike),
    hasOtp: safeBool(f.hasOtp),
    fieldCount:
      Number.isInteger(f.fieldCount) && f.fieldCount >= 0 && f.fieldCount < 1e4 ? f.fieldCount : 0,
    hiddenFields:
      Number.isInteger(f.hiddenFields) && f.hiddenFields >= 0 && f.hiddenFields < 1e4
        ? f.hiddenFields
        : 0,
  };
}

function safeAuthFlow(a) {
  if (!a || typeof a !== "object" || Array.isArray(a)) return null;
  return {
    anomalies: safeArr(a.anomalies, 32)
      .filter((x) => x && typeof x === "object" && !Array.isArray(x))
      .map((x) => ({
        id: safeStr(x.id, 64),
        severity: safeStr(x.severity, 16),
        // Canonical field name across the pipeline is `explain` (set by
        // buildAuthFlowSnapshot in content.js and authFlowGraph.js, read by
        // behavioral rules and the explainability layer). Accept `detail`
        // as a legacy alias so an older content script paired with a newer
        // background never produces blank popup text.
        explain: safeStr(x.explain || x.detail, 256),
      })),
    state: safeStr(a.state, 32),
  };
}

export function sanitizePageContext(ctx) {
  if (!ctx || typeof ctx !== "object" || Array.isArray(ctx)) return null;
  if (Object.keys(ctx).length > MAX_PAYLOAD_KEYS) return null;
  return Object.freeze({
    pageOrigin: safeStr(ctx.pageOrigin, PCTX_MAX_SMALL_STR),
    title: safeStr(ctx.title, PCTX_MAX_SMALL_STR),
    visibleText: safeStr(ctx.visibleText, PCTX_MAX_STR),
    favicon: safeStr(ctx.favicon, PCTX_MAX_SMALL_STR),
    hasPasswordField: safeBool(ctx.hasPasswordField),
    topLevelIframe: safeBool(ctx.topLevelIframe),
    scripts: safeStrArr(ctx.scripts),
    styles: safeStrArr(ctx.styles),
    images: safeStrArr(ctx.images),
    links: safeStrArr(ctx.links),
    oauthButtons: safeStrArr(ctx.oauthButtons, PCTX_MAX_OAUTH, 64),
    forms: safeArr(ctx.forms, PCTX_MAX_FORMS).map(safeForm).filter(Boolean),
    authFlow: safeAuthFlow(ctx.authFlow),
  });
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
    if (!m || typeof m.context !== "object" || m.context === null || Array.isArray(m.context))
      return { ok: false, error: "pageContext.context" };
    if (tooManyKeys(m.context)) return { ok: false, error: "pageContext.size" };
    // Strict schema normalization — downstream code never sees raw input.
    const clean = sanitizePageContext(m.context);
    if (!clean) return { ok: false, error: "pageContext.shape" };
    return { ok: true, value: { context: clean } };
  },
  getSettings: () => ({ ok: true, value: {} }),
  saveSettings: (m) => {
    if (!m || typeof m.patch !== "object" || m.patch === null)
      return { ok: false, error: "saveSettings.patch" };
    if (tooManyKeys(m.patch)) return { ok: false, error: "saveSettings.size" };
    if (m.patch.detection?.sensitivity != null && !SENSITIVITY.has(m.patch.detection.sensitivity))
      return { ok: false, error: "saveSettings.sensitivity" };
    return { ok: true, value: { patch: m.patch } };
  },
  getActivity: () => ({ ok: true, value: {} }),
  getHealth: () => ({ ok: true, value: {} }),
  clearCaches: () => ({ ok: true, value: {} }),
  logEvent: (m) => {
    if (!m?.entry || typeof m.entry !== "object") return { ok: false, error: "logEvent.entry" };
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
  refreshThreatFeed: () => ({ ok: true, value: {} }),
});

/** Types that mutate persistent trust / learning state. */
export const TRUST_MUTATION_TYPES = Object.freeze(
  new Set(["trustForSession", "saveSettings", "clearCaches", "logEvent", "refreshThreatFeed"]),
);

/**
 * Validate an incoming message. Returns { ok, type, value, error }.
 * Rejects unknown types, malformed envelopes, and oversized payloads.
 */
export function validateMessage(msg) {
  if (!msg || typeof msg !== "object") return { ok: false, error: "not-an-object" };
  const type = msg.type;
  if (typeof type !== "string" || !type) return { ok: false, error: "missing-type" };
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
  const fromExtUi =
    !!sender.url &&
    (sender.url.startsWith("chrome-extension://") || sender.url.startsWith("moz-extension://"));
  // Every accepted sender must originate either from a real tab (content
  // script) or from one of this extension's own pages. A bare runtime
  // sender (e.g. a co-installed extension's service worker) has neither.
  if (!fromTab && !fromExtUi) return false;
  // For non-tab senders, the origin/url must carry the extension scheme.
  if (
    !fromTab &&
    sender.origin &&
    !sender.origin.startsWith("chrome-extension://") &&
    !sender.origin.startsWith("moz-extension://")
  )
    return false;
  if (TRUST_MUTATION_TYPES.has(type)) {
    if (!fromTab && !fromExtUi) return false;
  }
  return true;
}
