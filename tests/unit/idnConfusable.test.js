import { describe, it, expect } from "vitest";
import { analyzeConfusable } from "../../extension/lib/idnConfusable.js";

describe("analyzeConfusable", () => {
  it("flags a Latin+Cyrillic mixed label as a critical spoof", () => {
    // "аpple" — the first letter is Cyrillic U+0430.
    const r = analyzeConfusable("аpple.com");
    expect(r.mixedScript).toBe(true);
    expect(r.confidence).toBeGreaterThanOrEqual(0.9);
    expect(r.signals[0].id).toBe("mixed-script-host");
    expect(r.signals[0].severity).toBe("critical");
  });

  it("flags Latin+Greek mixing", () => {
    // "pаypal" with a Greek omicron-like substitution in the label.
    const r = analyzeConfusable("gοogle.com"); // Greek omicron ο
    expect(r.mixedScript).toBe(true);
  });

  it("does NOT flag a pure-Latin hostname", () => {
    expect(analyzeConfusable("apple.com").mixedScript).toBe(false);
    expect(analyzeConfusable("my-secure-bank.co.uk").mixedScript).toBe(false);
  });

  it("does NOT flag digits or hyphens as a second script", () => {
    expect(analyzeConfusable("a1-b2-c3.com").mixedScript).toBe(false);
  });

  it("treats Latin+Han as unusual but not a critical brand spoof", () => {
    const r = analyzeConfusable("中文abc.com"); // 中文abc
    expect(r.mixedScript).toBe(true);
    expect(r.confidence).toBeLessThan(0.9);
    expect(r.signals[0].severity).toBe("high");
  });

  it("is safe on empty / bad input", () => {
    expect(analyzeConfusable("").mixedScript).toBe(false);
    expect(analyzeConfusable(null).mixedScript).toBe(false);
  });
});
