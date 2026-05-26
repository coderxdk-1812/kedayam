// Kedayam — Browser Capability Abstraction (M8/M9).
//
// Centralizes every browser/global feature lookup so the rest of the codebase
// never sprinkles `if (chrome...)` / `typeof navigator...` checks. The probe
// returns a frozen capability map; consumers branch on capability booleans.
//
// Failure modes degrade *silently* — a missing capability turns into a
// no-op, never a thrown error or noisy warning. This is the M9 degraded-
// mode guarantee: KEDAYAM must never escalate suspicion because a browser
// API changed or was disabled.

let _cached = null;

export function detectCapabilities(g = globalThis) {
  if (_cached) return _cached;
  const safe = (fn, fallback = false) => { try { return fn(); } catch { return fallback; } };

  const nav = safe(() => g.navigator, null);
  const chrome = safe(() => g.chrome, null);
  const browser = safe(() => g.browser, null);
  const runtime = chrome?.runtime || browser?.runtime || null;
  const storage = chrome?.storage || browser?.storage || null;
  const scripting = chrome?.scripting || browser?.scripting || null;

  const caps = Object.freeze({
    runtime: !!runtime,
    storageLocal: !!storage?.local,
    storageManaged: !!storage?.managed,
    scripting: !!scripting,
    scriptingMainWorld: !!(scripting?.executeScript &&
      safe(() => scripting.executeScript.length >= 1)),
    clipboardRead: safe(() => typeof nav?.clipboard?.readText === "function"),
    clipboardWrite: safe(() => typeof nav?.clipboard?.writeText === "function"),
    shadowDom: safe(() => typeof g.ShadowRoot !== "undefined"),
    mutationObserver: safe(() => typeof g.MutationObserver !== "undefined"),
    csp: safe(() => typeof g.TrustedTypePolicyFactory !== "undefined" ||
      typeof g.trustedTypes !== "undefined"),
    intersectionObserver: safe(() => typeof g.IntersectionObserver !== "undefined"),
    weakRef: safe(() => typeof g.WeakRef === "function"),
    performance: safe(() => typeof g.performance?.now === "function"),
    firefox: safe(() => !!browser && !chrome),
    chromium: !!chrome,
  });
  _cached = caps;
  return caps;
}

/** Convenience: run `fn` only if every named capability is present. */
export function withCapabilities(names, fn, fallback) {
  const c = detectCapabilities();
  for (const n of names) if (!c[n]) return typeof fallback === "function" ? fallback() : fallback;
  try { return fn(c); } catch { return typeof fallback === "function" ? fallback() : fallback; }
}

/** Test-only: clear the cached capabilities snapshot. */
export function _resetCapabilities() { _cached = null; }
