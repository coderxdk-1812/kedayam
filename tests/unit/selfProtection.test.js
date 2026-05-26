import { describe, it, expect } from "vitest";
import {
  safeExecRegex, safeMatchAll, boundedString, boundedArray,
  safeJSONParse, assertEnvelope, verifyModuleIntegrity, SELF_PROTECTION_LIMITS,
} from "../../extension/lib/selfProtection.js";

describe("selfProtection", () => {
  it("safeExecRegex returns null on oversized input", () => {
    const huge = "a".repeat(SELF_PROTECTION_LIMITS.STRING_MAX + 1);
    expect(safeExecRegex(/a/, huge)).toBeNull();
  });
  it("safeExecRegex works on normal input", () => {
    const m = safeExecRegex(/(foo)/, "barfoo");
    expect(m?.[1]).toBe("foo");
  });
  it("safeMatchAll caps matches", () => {
    const out = safeMatchAll(/a/, "a".repeat(500), { maxMatches: 50 });
    expect(out.length).toBeLessThanOrEqual(50);
  });
  it("safeMatchAll handles zero-width regex safely", () => {
    const out = safeMatchAll(/b*/, "aaa", { maxMatches: 20 });
    expect(out.length).toBeLessThanOrEqual(20);
  });
  it("boundedString clamps length and coerces non-strings", () => {
    expect(boundedString("abc", 2)).toBe("ab");
    expect(boundedString(123)).toBe("");
  });
  it("boundedArray clamps length", () => {
    expect(boundedArray([1, 2, 3, 4], 2).length).toBe(2);
    expect(boundedArray("nope")).toEqual([]);
  });
  it("safeJSONParse rejects oversize", () => {
    expect(safeJSONParse("x".repeat(2_000_000))).toBeNull();
    expect(safeJSONParse("not json")).toBeNull();
    expect(safeJSONParse('{"a":1}')?.a).toBe(1);
  });
  it("assertEnvelope rejects prototype pollution and bad shapes", () => {
    expect(assertEnvelope(null)).toBe(false);
    expect(assertEnvelope({})).toBe(false);
    expect(assertEnvelope({ type: "" })).toBe(false);
    expect(assertEnvelope({ type: "ok" })).toBe(true);
    expect(assertEnvelope(JSON.parse('{"type":"ok","__proto__":{}}'))).toBe(false);
    expect(assertEnvelope({ type: "ok" }, ["ok"])).toBe(true);
    expect(assertEnvelope({ type: "nope" }, ["ok"])).toBe(false);
  });
  it("verifyModuleIntegrity catches missing/shrunk registries", () => {
    expect(verifyModuleIntegrity("x", null, 1).ok).toBe(false);
    expect(verifyModuleIntegrity("x", Object.freeze({a:1,b:2}), 5).ok).toBe(false);
    expect(verifyModuleIntegrity("x", Object.freeze({a:1,b:2}), 2).ok).toBe(true);
  });
});
