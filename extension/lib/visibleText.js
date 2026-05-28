// Kedayam — accessibility-aware DOM visibility helper.
//
// Used by the content script's page-context collector to ensure only
// *user-visible* text contributes to phishing keyword scoring, brand
// keyword detection, and the human-readable explanation surface.
//
// Excluded:
//   - <script>, <style>, <template>, <noscript> (never rendered)
//   - display: none / visibility: hidden | collapse
//   - opacity: 0
//   - aria-hidden="true" anywhere up the tree (assistive tech ignores it)
//   - zero-area boxes (off-screen "trap" nodes)
//
// Preserved:
//   - visible auth prompts and labels
//   - screen-reader-targeted but visible content (no over-filtering)
//   - sticky/fixed elements with non-zero size
//
// The helper is intentionally best-effort: on any unexpected failure it
// returns true (i.e. "visible"), so a quirky page never silently strips
// real user-facing text.

const HIDDEN_TAGS = new Set(["SCRIPT", "STYLE", "TEMPLATE", "NOSCRIPT"]);

/**
 * @param {Element} el
 * @param {(el: Element) => CSSStyleDeclaration | null} [getStyle]
 *        Optional injector for computed style lookups (test-friendly).
 * @returns {boolean}
 */
export function isUserVisible(el, getStyle) {
  try {
    if (!el || typeof el !== "object" || !el.tagName) return false;
    if (HIDDEN_TAGS.has(el.tagName)) return false;
    if (typeof el.closest === "function" &&
        el.closest('[aria-hidden="true"]')) return false;
    const lookup = getStyle ||
      (typeof globalThis.getComputedStyle === "function"
        ? globalThis.getComputedStyle.bind(globalThis) : null);
    const cs = lookup ? lookup(el) : null;
    if (cs) {
      if (cs.display === "none") return false;
      if (cs.visibility === "hidden" || cs.visibility === "collapse") return false;
      const op = parseFloat(cs.opacity);
      if (!Number.isNaN(op) && op === 0) return false;
      // Bounded, high-confidence CSS hiding patterns. Each check is a cheap
      // string/regex test against an already-fetched style object — no
      // additional reflow, no ancestor walk. Default-to-visible on parse
      // uncertainty (see file header).
      const tf = typeof cs.transform === "string" ? cs.transform : "";
      if (tf && tf !== "none") {
        // translate(X|Y|3d)(...) with a coordinate <= -3000px is a classic
        // offscreen-trap pattern (e.g. translateX(-9999px)).
        const m = tf.match(/translate(?:X|Y|3d)?\(\s*(-?\d+(?:\.\d+)?)(px|rem|em)?/i);
        if (m) {
          const v = parseFloat(m[1]);
          if (!Number.isNaN(v) && v <= -3000) return false;
        }
      }
      // clip-path: inset(100%) / inset(50% 50% 50% 50%) — fully clipped.
      const cp = typeof cs.clipPath === "string" ? cs.clipPath : "";
      if (/inset\(\s*100%\s*\)/i.test(cp)) return false;
      // Legacy clip: rect(0,0,0,0) — the canonical sr-only hide pattern,
      // BUT sr-only utilities typically pair this with width/height: 1px
      // and position: absolute to keep screen-reader access. We DO want
      // to exclude these from visible-text scoring since a sighted user
      // cannot perceive them, while leaving accessibility unaffected
      // (browser AT reads them directly from the DOM, not from us).
      const clip = typeof cs.clip === "string" ? cs.clip : "";
      if (/rect\(\s*0(?:px)?\s*,?\s*0(?:px)?\s*,?\s*0(?:px)?\s*,?\s*0(?:px)?\s*\)/i.test(clip)) {
        return false;
      }
      // Extreme offscreen absolute/fixed positioning (top/left <= -3000px).
      if (cs.position === "absolute" || cs.position === "fixed") {
        const offscreen = (v) => {
          if (typeof v !== "string") return false;
          const m2 = v.match(/^(-?\d+(?:\.\d+)?)(px)?$/);
          if (!m2) return false;
          const n = parseFloat(m2[1]);
          return !Number.isNaN(n) && n <= -3000;
        };
        if (offscreen(cs.left) || offscreen(cs.top)) return false;
      }
    }
    if (typeof el.getBoundingClientRect === "function") {
      const r = el.getBoundingClientRect();
      if (r && r.width === 0 && r.height === 0) return false;
    }

    return true;
  } catch {
    return true;
  }
}

/**
 * Extract user-visible text from a list of element candidates. Same contract
 * as the inline collector in extension/content/content.js — the lib version
 * is exported so the visibility rules are testable in isolation.
 *
 * @param {Iterable<Element>} elements
 * @param {{ titleText?: string, maxLen?: number,
 *           getStyle?: (el: Element) => CSSStyleDeclaration | null }} [opts]
 * @returns {string}
 */
export function extractVisibleText(elements, opts = {}) {
  const { titleText = "", maxLen = 4000, getStyle } = opts;
  const parts = [];
  if (titleText) parts.push(String(titleText).trim());
  for (const el of elements) {
    if (!isUserVisible(el, getStyle)) continue;
    const t = (el.textContent || "").trim();
    if (t) parts.push(t);
  }
  return parts.join(" ").slice(0, Math.max(0, maxLen));
}
