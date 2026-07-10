// Phase R2 — prototype-pollution & merge safety regression suite.

import { describe, it, expect } from "vitest";
import { deepMerge } from "../../extension/lib/storage.js";

describe("R2 — deepMerge forbidden-key sanitization", () => {
  it("ignores __proto__ in source override", () => {
    const out = deepMerge({ a: 1 }, JSON.parse('{"__proto__":{"polluted":true},"a":2}'));
    expect(out.a).toBe(2);
    // Nothing leaks onto Object.prototype.
    expect({}.polluted).toBeUndefined();
    expect(Object.prototype.polluted).toBeUndefined();
  });

  it("ignores prototype and constructor keys", () => {
    const out = deepMerge({}, JSON.parse('{"prototype":{"x":1},"constructor":{"y":2}}'));
    expect(out.prototype).toBeUndefined();
    expect(out.constructor).toBe(Object); // unchanged prototype chain
  });

  it("ignores nested forbidden keys at any depth", () => {
    const payload = JSON.parse(
      '{"detection":{"__proto__":{"sneaky":true},"sensitivity":"strict"}}',
    );
    const out = deepMerge({ detection: { sensitivity: "balanced" } }, payload);
    expect(out.detection.sensitivity).toBe("strict");
    expect({}.sneaky).toBeUndefined();
    expect(out.detection.sneaky).toBeUndefined();
  });

  it("does not mutate source objects", () => {
    const base = { a: { b: 1 } };
    const baseCopy = JSON.parse(JSON.stringify(base));
    deepMerge(base, { a: { b: 2 } });
    expect(base).toEqual(baseCopy);
  });

  it("result is a plain object with default prototype", () => {
    const out = deepMerge({ a: 1 }, { b: 2 });
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
  });

  it("preserves deterministic merge behavior for normal keys", () => {
    const out1 = deepMerge({ x: 1, y: { z: 2 } }, { y: { z: 3, w: 4 } });
    const out2 = deepMerge({ x: 1, y: { z: 2 } }, { y: { z: 3, w: 4 } });
    expect(out1).toEqual({ x: 1, y: { z: 3, w: 4 } });
    expect(out1).toEqual(out2);
  });

  it("array overrides replace base arrays (existing semantics preserved)", () => {
    const out = deepMerge({ list: [1, 2] }, { list: [3] });
    expect(out.list).toEqual([3]);
  });

  it("polluted Object.prototype check across whole suite", () => {
    // Final guard: regardless of prior tests, Object.prototype is clean.
    expect(Object.prototype.polluted).toBeUndefined();
    expect(Object.prototype.sneaky).toBeUndefined();
    expect({}.polluted).toBeUndefined();
  });
});
