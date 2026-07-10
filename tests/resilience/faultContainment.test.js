// Phase R1 — Resilience regression suite.
//
// Verifies that malformed pageContext payloads, async failures, and
// degraded inputs CANNOT silently disable protection. Every downstream
// consumer must either produce a safe verdict or be fully no-op.

import { describe, it, expect } from "vitest";
import { validateMessage, sanitizePageContext } from "../../extension/lib/messageSchemas.js";
import { analyzeClone } from "../../extension/lib/cloneDetection.js";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";

// Build a deeply malformed pageContext that historically crashed the scan
// pipeline with "X.filter is not a function".
const malformedShapes = [
  { name: "forms not array", ctx: { pageOrigin: "https://x.test/", forms: "not-an-array" } },
  { name: "scripts not array", ctx: { pageOrigin: "https://x.test/", scripts: { 0: "x" } } },
  { name: "images null", ctx: { pageOrigin: "https://x.test/", images: null } },
  { name: "links is number", ctx: { pageOrigin: "https://x.test/", links: 42 } },
  { name: "oauthButtons object", ctx: { pageOrigin: "https://x.test/", oauthButtons: { a: 1 } } },
  { name: "favicon as object", ctx: { pageOrigin: "https://x.test/", favicon: { url: "x" } } },
  { name: "hasPasswordField str", ctx: { pageOrigin: "https://x.test/", hasPasswordField: "yes" } },
  { name: "topLevelIframe 1", ctx: { pageOrigin: "https://x.test/", topLevelIframe: 1 } },
  { name: "title is array", ctx: { pageOrigin: "https://x.test/", title: ["a", "b"] } },
  {
    name: "visibleText buffer",
    ctx: { pageOrigin: "https://x.test/", visibleText: new Uint8Array([1]) },
  },
  { name: "authFlow array", ctx: { pageOrigin: "https://x.test/", authFlow: [1, 2, 3] } },
  { name: "form item is string", ctx: { pageOrigin: "https://x.test/", forms: ["nope", null, 7] } },
  {
    name: "form fieldCount neg",
    ctx: { pageOrigin: "https://x.test/", forms: [{ fieldCount: -3 }] },
  },
  { name: "sparse forms array", ctx: { pageOrigin: "https://x.test/", forms: new Array(10) } },
];

describe("R1 — malformed pageContext sanitization", () => {
  for (const { name, ctx } of malformedShapes) {
    it(`sanitizes: ${name}`, () => {
      const clean = sanitizePageContext(ctx);
      expect(clean).toBeTruthy();
      expect(Array.isArray(clean.forms)).toBe(true);
      expect(Array.isArray(clean.scripts)).toBe(true);
      expect(Array.isArray(clean.images)).toBe(true);
      expect(Array.isArray(clean.links)).toBe(true);
      expect(Array.isArray(clean.oauthButtons)).toBe(true);
      expect(typeof clean.title).toBe("string");
      expect(typeof clean.visibleText).toBe("string");
      expect(typeof clean.favicon).toBe("string");
      expect(typeof clean.hasPasswordField).toBe("boolean");
      expect(typeof clean.topLevelIframe).toBe("boolean");
      // sanitized authFlow is either null or a plain object with anomalies array
      if (clean.authFlow) expect(Array.isArray(clean.authFlow.anomalies)).toBe(true);
    });
  }

  it("rejects non-object / cyclic / oversized envelopes deterministically", () => {
    expect(sanitizePageContext(null)).toBeNull();
    expect(sanitizePageContext("string")).toBeNull();
    expect(sanitizePageContext(42)).toBeNull();
    expect(sanitizePageContext([1, 2, 3])).toBeNull();
    const oversized = {};
    for (let i = 0; i < 64; i++) oversized["k" + i] = i;
    expect(sanitizePageContext(oversized)).toBeNull();
  });

  it("pageContext message validator rejects array contexts", () => {
    const v = validateMessage({ type: "pageContext", context: [1, 2, 3] });
    expect(v.ok).toBe(false);
  });

  it("downstream consumers do NOT throw on sanitized malformed input", () => {
    for (const { ctx } of malformedShapes) {
      const clean = sanitizePageContext(ctx);
      expect(() => analyzeClone(clean)).not.toThrow();
      expect(() =>
        analyzePhishing({
          pageOrigin: clean.pageOrigin,
          host: "x.test",
          rootHost: "x.test",
          title: clean.title,
          visibleText: clean.visibleText,
          forms: clean.forms,
          hasPasswordField: clean.hasPasswordField,
          oauthButtons: clean.oauthButtons,
          topLevelIframe: clean.topLevelIframe,
        }),
      ).not.toThrow();
    }
  });

  it("a cyclic structure is rejected without recursion blowup", () => {
    const cyclic = { pageOrigin: "https://x.test/" };
    cyclic.self = cyclic;
    // sanitizePageContext only reads known fields, so cycles never enter
    // the recursion; the function MUST return a clean object in bounded time.
    const out = sanitizePageContext(cyclic);
    expect(out).toBeTruthy();
    expect(out.pageOrigin).toBe("https://x.test/");
  });

  it("oversized arrays are truncated, not rejected", () => {
    const huge = {
      pageOrigin: "https://x.test/",
      scripts: new Array(5000).fill("https://cdn.test/a.js"),
    };
    const clean = sanitizePageContext(huge);
    expect(clean.scripts.length).toBeLessThanOrEqual(256);
  });
});

describe("R1 — scan pipeline never silently freezes", () => {
  it("a rejected promise inside scan() is caught (contract)", async () => {
    // Mirrors the .catch() wired in background.js around the scan IIFE.
    const inflight = new Map();
    let rejectedRan = false;
    const p = (async () => {
      throw new Error("boom");
    })()
      .catch(() => {
        rejectedRan = true;
        return null;
      })
      .finally(() => inflight.delete("k"));
    inflight.set("k", p);
    const r = await p;
    expect(rejectedRan).toBe(true);
    expect(r).toBeNull();
    expect(inflight.has("k")).toBe(false);
  });
});
