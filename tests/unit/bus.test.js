import { describe, it, expect } from "vitest";
import { makeEnvelope, isValidEnvelope, NonceCache, ENVELOPE_VERSION } from "../../extension/lib/bus.js";

describe("envelope", () => {
  it("creates a valid envelope", () => {
    const e = makeEnvelope("scan", { url: "https://x" });
    expect(e.v).toBe(ENVELOPE_VERSION);
    expect(e.type).toBe("scan");
    expect(e.payload.url).toBe("https://x");
    expect(typeof e.nonce).toBe("string");
    expect(isValidEnvelope(e)).toBe(true);
  });
  it("rejects mismatched versions", () => {
    expect(isValidEnvelope({ v: 99, type: "x", nonce: "n" })).toBe(false);
  });
  it("rejects missing fields", () => {
    expect(isValidEnvelope({ v: 1, nonce: "n" })).toBe(false);
    expect(isValidEnvelope(null)).toBe(false);
  });
});

describe("NonceCache", () => {
  it("returns false for first-seen and true for repeats", () => {
    const c = new NonceCache(4);
    expect(c.seen("a")).toBe(false);
    expect(c.seen("a")).toBe(true);
    expect(c.seen("b")).toBe(false);
  });
  it("evicts oldest beyond max", () => {
    const c = new NonceCache(2);
    c.seen("a"); c.seen("b"); c.seen("c");
    expect(c.seen("a")).toBe(false);
    expect(c.seen("c")).toBe(true);
  });
});