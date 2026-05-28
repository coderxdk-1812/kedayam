// Phase V2 — bounded CSS visibility edge-case handling.
//
// Covers transform offscreen traps, clip-path:inset(100%), legacy
// clip:rect(0,0,0,0) sr-only, and extreme negative absolute positioning.
// Default-to-visible on uncertainty is preserved — see
// extension/lib/visibleText.js header.

import { describe, it, expect } from "vitest";
import {
  isUserVisible, extractVisibleText,
} from "../../extension/lib/visibleText.js";

function node({
  tag = "P", text = "v", aria = null, parent = null,
  style = {}, rect = { width: 100, height: 20 },
} = {}) {
  return {
    tagName: tag,
    textContent: text,
    _aria: aria,
    _parent: parent,
    _style: {
      display: "block", visibility: "visible", opacity: "1",
      transform: "none", clipPath: "none", clip: "auto",
      position: "static", left: "auto", top: "auto",
      ...style,
    },
    getBoundingClientRect: () => rect,
    closest(sel) {
      if (sel === '[aria-hidden="true"]') {
        let cur = this;
        while (cur) { if (cur._aria === "true") return cur; cur = cur._parent; }
      }
      return null;
    },
  };
}
const lookup = (el) => el._style;

describe("V2 — CSS visibility edge cases", () => {
  it("excludes translateX(-9999px) offscreen text", () => {
    const n = node({ text: "Enter password",
      style: { transform: "translateX(-9999px)" } });
    expect(isUserVisible(n, lookup)).toBe(false);
  });

  it("excludes translate3d(-9999px,0,0) offscreen text", () => {
    const n = node({ text: "x",
      style: { transform: "translate3d(-9999px, 0, 0)" } });
    expect(isUserVisible(n, lookup)).toBe(false);
  });

  it("keeps small translate offsets visible", () => {
    const n = node({ text: "Sign in",
      style: { transform: "translateX(-20px)" } });
    expect(isUserVisible(n, lookup)).toBe(true);
  });

  it("excludes clip-path: inset(100%)", () => {
    const n = node({ text: "hidden",
      style: { clipPath: "inset(100%)" } });
    expect(isUserVisible(n, lookup)).toBe(false);
  });

  it("excludes legacy clip: rect(0,0,0,0) sr-only pattern", () => {
    const n = node({ text: "sr-only secret",
      style: { clip: "rect(0, 0, 0, 0)" } });
    expect(isUserVisible(n, lookup)).toBe(false);
  });

  it("excludes extreme negative absolute positioning", () => {
    const n = node({ text: "offscreen",
      style: { position: "absolute", left: "-9999px", top: "0" } });
    expect(isUserVisible(n, lookup)).toBe(false);
  });

  it("keeps visible auth labels with normal positioning", () => {
    const n = node({ text: "Email address" });
    expect(isUserVisible(n, lookup)).toBe(true);
  });

  it("keeps visible labels even when transform is set to none", () => {
    const n = node({ text: "Password",
      style: { transform: "none" } });
    expect(isUserVisible(n, lookup)).toBe(true);
  });

  it("defaults to visible on unparseable transform value", () => {
    const n = node({ text: "Continue",
      style: { transform: "matrix(1,0,0,1,0,0)" } });
    expect(isUserVisible(n, lookup)).toBe(true);
  });

  it("extracts only visible text from a mixed tree", () => {
    const nodes = [
      node({ text: "Sign in to your account" }),
      node({ text: "phishing-hidden",
        style: { transform: "translateX(-9999px)" } }),
      node({ text: "Password" }),
      node({ text: "sr-only-trap",
        style: { clip: "rect(0,0,0,0)" } }),
      node({ text: "clip-trap",
        style: { clipPath: "inset(100%)" } }),
      node({ text: "offscreen-trap",
        style: { position: "fixed", left: "-9999px", top: "-9999px" } }),
      node({ text: "Continue" }),
    ];
    const out = extractVisibleText(nodes, { getStyle: lookup, maxLen: 1000 });
    expect(out).toContain("Sign in to your account");
    expect(out).toContain("Password");
    expect(out).toContain("Continue");
    expect(out).not.toContain("phishing-hidden");
    expect(out).not.toContain("sr-only-trap");
    expect(out).not.toContain("clip-trap");
    expect(out).not.toContain("offscreen-trap");
  });

  it("extraction is deterministic across repeated runs", () => {
    const nodes = [
      node({ text: "a" }),
      node({ text: "b", style: { transform: "translateY(-9999px)" } }),
      node({ text: "c" }),
    ];
    const r1 = extractVisibleText(nodes, { getStyle: lookup });
    const r2 = extractVisibleText(nodes, { getStyle: lookup });
    expect(r1).toBe(r2);
  });

  it("traversal cost stays bounded over many nodes", () => {
    const nodes = [];
    for (let i = 0; i < 2000; i++) {
      nodes.push(node({ text: `t${i}`,
        style: i % 3 === 0 ? { transform: "translateX(-9999px)" } : {} }));
    }
    const t0 = performance.now();
    extractVisibleText(nodes, { getStyle: lookup, maxLen: 100000 });
    const ms = performance.now() - t0;
    expect(ms).toBeLessThan(500);
  });
});
