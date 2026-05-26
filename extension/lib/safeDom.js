// Kedayam — Safe DOM access.
//
// We capture immutable references to native DOM APIs at module load, BEFORE
// the page's scripts execute. Subsequent monkey-patching of `Element.prototype.*`,
// `Node.prototype.*`, or `Document.prototype.*` cannot affect us — every call
// site uses Reflect.apply against the frozen reference.
//
// This protects against:
//   • prototype pollution (page redefines querySelector to lie about login forms)
//   • anti-analysis scripts that wrap getAttribute to hide their real target
//   • naive content-script scanners that pick up poisoned values
//
// IMPORTANT: import this module FIRST in any content script that scans the DOM.

const NATIVE = (() => {
  const D = Document.prototype;
  const E = Element.prototype;
  const N = Node.prototype;
  const HTMLEl = HTMLElement.prototype;
  const HTMLInput = typeof HTMLInputElement !== "undefined"
    ? HTMLInputElement.prototype : null;

  return Object.freeze({
    documentQuerySelector: D.querySelector,
    documentQuerySelectorAll: D.querySelectorAll,
    elementQuerySelector: E.querySelector,
    elementQuerySelectorAll: E.querySelectorAll,
    getAttribute: E.getAttribute,
    setAttribute: E.setAttribute,
    hasAttribute: E.hasAttribute,
    appendChild: N.appendChild,
    removeChild: N.removeChild,
    contains: N.contains,
    addEventListener: typeof EventTarget !== "undefined"
      ? EventTarget.prototype.addEventListener : null,
    removeEventListener: typeof EventTarget !== "undefined"
      ? EventTarget.prototype.removeEventListener : null,
    getRootNode: N.getRootNode,
    // descriptors used for shadow-root traversal
    shadowRootDesc: Object.getOwnPropertyDescriptor(E, "shadowRoot"),
    childNodesDesc: Object.getOwnPropertyDescriptor(N, "childNodes"),
    textContentDesc: Object.getOwnPropertyDescriptor(N, "textContent"),
    inputTypeDesc: HTMLInput && Object.getOwnPropertyDescriptor(HTMLInput, "type"),
    inputValueDesc: HTMLInput && Object.getOwnPropertyDescriptor(HTMLInput, "value"),
    inputNameDesc: HTMLInput && Object.getOwnPropertyDescriptor(HTMLInput, "name"),
  });
})();

const RA = Reflect.apply;

export function qs(root, sel) {
  if (!root || !sel) return null;
  const fn = root === document ? NATIVE.documentQuerySelector : NATIVE.elementQuerySelector;
  try { return RA(fn, root, [sel]); } catch { return null; }
}
export function qsa(root, sel) {
  if (!root || !sel) return [];
  const fn = root === document ? NATIVE.documentQuerySelectorAll : NATIVE.elementQuerySelectorAll;
  try { return Array.from(RA(fn, root, [sel])); } catch { return []; }
}
export function attr(el, name) {
  if (!el || !name) return null;
  try { return RA(NATIVE.getAttribute, el, [name]); } catch { return null; }
}
export function textOf(el) {
  if (!el || !NATIVE.textContentDesc?.get) return "";
  try { return RA(NATIVE.textContentDesc.get, el, []) || ""; } catch { return ""; }
}
export function inputType(el) {
  if (!el || !NATIVE.inputTypeDesc?.get) return "";
  try { return (RA(NATIVE.inputTypeDesc.get, el, []) || "").toLowerCase(); } catch { return ""; }
}
export function inputName(el) {
  if (!el || !NATIVE.inputNameDesc?.get) return "";
  try { return RA(NATIVE.inputNameDesc.get, el, []) || ""; } catch { return ""; }
}
export function getShadowRoot(el) {
  if (!el || !NATIVE.shadowRootDesc?.get) return null;
  try { return RA(NATIVE.shadowRootDesc.get, el, []); } catch { return null; }
}

/**
 * Recursively walk open shadow roots from a starting node, invoking `visit`
 * with each (root, depth). Bounded to prevent DoS against runaway DOMs.
 */
export function walkShadowRoots(start, visit, { maxNodes = 5_000, maxDepth = 8 } = {}) {
  if (!start) return;
  let count = 0;
  const queue = [[start, 0]];
  while (queue.length) {
    const [node, depth] = queue.shift();
    if (++count > maxNodes || depth > maxDepth) return;
    try { visit(node, depth); } catch {}
    const all = qsa(node, "*");
    for (const el of all) {
      const sr = getShadowRoot(el);
      if (sr) queue.push([sr, depth + 1]);
    }
  }
}

/**
 * Listener registration that records its target/event/fn so the caller can
 * dispose every listener with a single call — fixes long-session listener leaks.
 */
export function createListenerScope() {
  const items = [];
  return {
    on(target, type, handler, options) {
      if (!target || !NATIVE.addEventListener) return;
      try { RA(NATIVE.addEventListener, target, [type, handler, options]); items.push([target, type, handler, options]); }
      catch {}
    },
    dispose() {
      for (const [t, ty, h, o] of items) {
        try { RA(NATIVE.removeEventListener, t, [ty, h, o]); } catch {}
      }
      items.length = 0;
    },
    size() { return items.length; },
  };
}

export const _native = NATIVE;
