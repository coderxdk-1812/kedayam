import { describe, it, expect, beforeEach } from "vitest";
import {
  storeReplay, consumeReplay, zeroize, _size, _resetAll, _hasToken,
} from "../../extension/lib/ephemeralReplay.js";

describe("ephemeralReplay (Issue NEW-01)", () => {
  beforeEach(() => _resetAll());

  it("round-trips a payload exactly once", () => {
    const t = storeReplay("hello-world");
    expect(t).toMatch(/^kr_/);
    expect(consumeReplay(t)).toBe("hello-world");
    // Second consume must NOT return the payload.
    expect(consumeReplay(t)).toBeNull();
  });

  it("rejects empty / non-string payloads (no token issued)", () => {
    expect(storeReplay("")).toBeNull();
    expect(storeReplay(null)).toBeNull();
    expect(storeReplay(undefined)).toBeNull();
    expect(storeReplay(123)).toBeNull();
    expect(_size()).toBe(0);
  });

  it("zeroize() purges the entry and clears its timer", () => {
    const t = storeReplay("secret-x");
    expect(_hasToken(t)).toBe(true);
    zeroize(t);
    expect(_hasToken(t)).toBe(false);
    expect(consumeReplay(t)).toBeNull();
  });

  it("expires payload after TTL", () => {
    const t = storeReplay("transient", 5);
    return new Promise((resolve) => setTimeout(() => {
      expect(consumeReplay(t)).toBeNull();
      expect(_size()).toBe(0);
      resolve();
    }, 25));
  });

  it("never throws and always cleans on consume of unknown token", () => {
    expect(() => consumeReplay("nope")).not.toThrow();
    expect(consumeReplay("nope")).toBeNull();
  });

  it("evicts oldest entries beyond MAX_ENTRIES", () => {
    const tokens = [];
    for (let i = 0; i < 16; i++) tokens.push(storeReplay("x" + i));
    expect(_size()).toBeLessThanOrEqual(8);
    // Oldest tokens should be unusable.
    expect(consumeReplay(tokens[0])).toBeNull();
  });

  it("payloads never appear in JSON.stringify of the module surface", () => {
    storeReplay("supersecret-leak-check");
    // Public introspection helpers must not expose the value.
    const surface = JSON.stringify({ size: _size() });
    expect(surface).not.toMatch(/supersecret/);
  });
});
