import { describe, it, expect } from "vitest";
import {
  decodePunycodeLabel,
  levenshtein,
  normalizeHomoglyphs,
  rootDomain,
  lookalikeAnalysis,
} from "../../extension/lib/lookalike.js";

describe("levenshtein", () => {
  it("returns 0 for equal strings", () => expect(levenshtein("abc", "abc")).toBe(0));
  it("counts a single substitution", () => expect(levenshtein("paypal", "paypa1")).toBe(1));
  it("counts insertion", () => expect(levenshtein("google", "gooogle")).toBe(1));
});

describe("rootDomain", () => {
  it("strips subdomain", () => expect(rootDomain("a.b.example.com")).toBe("example.com"));
  it("handles co.uk", () => expect(rootDomain("login.barclays.co.uk")).toBe("barclays.co.uk"));
});

describe("normalizeHomoglyphs", () => {
  it("maps cyrillic 'а' to latin a", () => {
    expect(normalizeHomoglyphs("p\u0430ypal.com")).toBe("paypal.com");
  });
});

describe("lookalikeAnalysis", () => {
  it("does not flag a known brand", () => {
    expect(lookalikeAnalysis("www.paypal.com").match).toBeNull();
  });
  it("flags a typosquat", () => {
    const r = lookalikeAnalysis("paypa1.com");
    expect(r.match).not.toBeNull();
    expect(r.match.brand).toBe("paypal.com");
    expect(r.confidence).toBeGreaterThan(0.5);
  });
  it("flags a homoglyph attack", () => {
    const r = lookalikeAnalysis("p\u0430ypal.com");
    expect(r.match).not.toBeNull();
    expect(r.confidence).toBeGreaterThanOrEqual(0.9);
  });
  it("decodes and flags punycode IDN hostnames", () => {
    expect(decodePunycodeLabel("xn--pypal-4ve")).toContain("а");
    const r = lookalikeAnalysis("xn--pypal-4ve.com");
    expect(r.match).not.toBeNull();
    expect(r.reasons.join(" ")).toMatch(/Punycode|look-alike/i);
  });
  it("flags brand name in unrelated host", () => {
    const r = lookalikeAnalysis("paypal.secure-login.tld");
    expect(r.reasons.length).toBeGreaterThan(0);
  });
});
