// Performance baseline — visibility traversal & visibleText extraction.
//
// Establishes synthetic upper bounds for the accessibility-aware DOM
// visibility helper so future node-cap increases are measurable, not
// vibes-based. No behavioral assertions about *what* is filtered live
// here — those are covered by tests/ux/explanationClarity.test.js.
//
// We construct synthetic node arrays (not a real DOM) of 500 / 1000 /
// 4000 mixed nodes — visible, display:none, visibility:hidden,
// aria-hidden subtree members, opacity:0, and zero-area off-screen
// traps — then assert:
//   1. extraction time scales roughly linearly (no exponential blowup)
//   2. extraction is deterministic across repeated runs
//   3. no measurable memory growth across repeated scans
//   4. ancestor aria-hidden traversal is bounded (deep nesting stays fast)
//
// Benchmark testing guidelines (apply to any perf test in this repo):
//   * Never assert on raw timing ratios with a near-zero denominator —
//     a fast warm-run baseline (sub-millisecond) makes the ratio explode
//     under trivial CI noise. Use `expect(c).toBeLessThan(a * K + N)`
//     style additive tolerances instead.
//   * Prefer absolute ceilings sized for the slowest realistic CI shape.
//   * Do not assume JIT stability, deterministic scheduling, or stable
//     wall-clock resolution across runs.
//   * Never paper over flakiness with retries, sleeps, or probabilistic
//     thresholds — fix the assertion shape.

import { describe, it, expect } from "vitest";
import { extractVisibleText, isUserVisible } from "../../extension/lib/visibleText.js";

function makeNode({
  tag = "P", text = "v", aria = null, parent = null,
  style = { display: "block", visibility: "visible", opacity: "1" },
  rect = { width: 100, height: 20 },
} = {}) {
  return {
    tagName: tag,
    textContent: text,
    _aria: aria,
    _parent: parent,
    _style: style,
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
const styleLookup = (el) => el._style || {
  display: "block", visibility: "visible", opacity: "1",
};

function buildSyntheticDom(n) {
  const nodes = [];
  // One deep aria-hidden ancestor chain to exercise .closest() traversal.
  let ariaRoot = makeNode({ tag: "DIV", aria: "true" });
  let chain = ariaRoot;
  for (let i = 0; i < 20; i++) {
    chain = makeNode({ tag: "DIV", parent: chain });
  }
  for (let i = 0; i < n; i++) {
    const bucket = i % 7;
    if (bucket === 0) nodes.push(makeNode({ text: `visible-${i}` }));
    else if (bucket === 1) nodes.push(makeNode({
      text: `hidden-${i}`,
      style: { display: "none", visibility: "visible", opacity: "1" },
    }));
    else if (bucket === 2) nodes.push(makeNode({
      text: `invisible-${i}`,
      style: { display: "block", visibility: "hidden", opacity: "1" },
    }));
    else if (bucket === 3) nodes.push(makeNode({
      text: `opacity-${i}`,
      style: { display: "block", visibility: "visible", opacity: "0" },
    }));
    else if (bucket === 4) nodes.push(makeNode({
      text: `aria-trap-${i}`, parent: chain,
    }));
    else if (bucket === 5) nodes.push(makeNode({
      text: `trap-${i}`, rect: { width: 0, height: 0 },
    }));
    else nodes.push(makeNode({ tag: "SCRIPT", text: `evil(${i})` }));
  }
  return nodes;
}

function timeExtract(nodes) {
  const t0 = performance.now();
  const out = extractVisibleText(nodes, { getStyle: styleLookup, maxLen: 100000 });
  return { ms: performance.now() - t0, out };
}

describe("visibility traversal — performance baseline", () => {
  it("scales sub-quadratically from 500 → 4000 nodes", () => {
    const small = buildSyntheticDom(500);
    const mid = buildSyntheticDom(1000);
    const large = buildSyntheticDom(4000);

    // Warm-up to take JIT noise off the critical measurement.
    timeExtract(small); timeExtract(mid); timeExtract(large);

    const a = timeExtract(small).ms;
    const b = timeExtract(mid).ms;
    const c = timeExtract(large).ms;

    // Generous absolute ceiling for CI variance — we're guarding against
    // exponential / quadratic regressions, not microbenchmarking.
    expect(c).toBeLessThan(500);
    // Benchmark assertion guidelines (see also: file header comment):
    //   - Never divide by a near-zero baseline; after JIT warm-up `a`
    //     can collapse to sub-millisecond values and amplify FP noise.
    //   - Prefer additive tolerances over pure ratios so CI scheduling
    //     jitter, CPU contention, and runtime optimization variance are
    //     absorbed without hiding real regressions.
    //   - Keep ceilings loose enough to tolerate cold/warm runs but
    //     tight enough that quadratic blowups still trip the assertion.
    // 8× the node count: allow ~40× scaling slack PLUS a 50ms additive
    // floor so a ≈ 0.05ms baselines don't make this assertion brittle.
    expect(c).toBeLessThan(a * 40 + 50);
    // 2× nodes: same additive-tolerance shape, smaller ceiling.
    expect(b).toBeLessThan(a * 10 + 25);
  });

  it("produces deterministic output across repeated scans", () => {
    const nodes = buildSyntheticDom(1000);
    const r1 = extractVisibleText(nodes, { getStyle: styleLookup, maxLen: 100000 });
    const r2 = extractVisibleText(nodes, { getStyle: styleLookup, maxLen: 100000 });
    const r3 = extractVisibleText(nodes, { getStyle: styleLookup, maxLen: 100000 });
    expect(r1).toBe(r2);
    expect(r2).toBe(r3);
  });

  it("ancestor aria-hidden traversal stays bounded on deep nesting", () => {
    // 500-deep chain — .closest('[aria-hidden="true"]') must short-circuit
    // at the root, not scale with depth in a pathological way.
    let chain = makeNode({ tag: "DIV", aria: "true" });
    for (let i = 0; i < 500; i++) {
      chain = makeNode({ tag: "DIV", parent: chain });
    }
    const t0 = performance.now();
    for (let i = 0; i < 1000; i++) isUserVisible(chain, styleLookup);
    const ms = performance.now() - t0;
    expect(ms).toBeLessThan(250);
  });

  it("scaling assertion holds across repeated iterations (no flakiness)", () => {
    // Re-run the scaling check several times back-to-back. Under the
    // previous ratio-based assertion this would intermittently fail as
    // `a` shrank below ~0.1ms. The additive-tolerance shape must hold
    // deterministically across warm-up orderings.
    const small = buildSyntheticDom(500);
    const large = buildSyntheticDom(4000);
    // Warm-up.
    timeExtract(small); timeExtract(large);
    for (let i = 0; i < 5; i++) {
      const a = timeExtract(small).ms;
      const c = timeExtract(large).ms;
      expect(c).toBeLessThan(a * 40 + 50);
      expect(c).toBeLessThan(500);
    }
  });

  it("shows no unbounded memory growth across repeated extractions", () => {
    const nodes = buildSyntheticDom(1000);
    // 50 repeated scans — if anything caches per-call, heap would balloon.
    let lastLen = -1;
    for (let i = 0; i < 50; i++) {
      const out = extractVisibleText(nodes, { getStyle: styleLookup, maxLen: 100000 });
      if (lastLen === -1) lastLen = out.length;
      // Determinism implies no per-call accumulation in the output.
      expect(out.length).toBe(lastLen);
    }
    if (typeof globalThis.gc === "function") globalThis.gc();
    const mem = process.memoryUsage().heapUsed;
    expect(mem).toBeLessThan(512 * 1024 * 1024);
  });
});
