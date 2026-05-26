import { describe, it, expect } from "vitest";
import { evaluateAll, RULES, RULES_BY_ID, REGISTRY_VERSION } from "../../extension/lib/rules/index.js";

describe("rule registry", () => {
  it("has stable shape and version", () => {
    expect(REGISTRY_VERSION).toBeGreaterThanOrEqual(1);
    expect(Object.isFrozen(RULES)).toBe(true);
    for (const r of RULES) {
      expect(typeof r.id).toBe("string");
      expect(typeof r.severity).toBe("string");
      expect(typeof r.evaluate).toBe("function");
    }
  });
  it("evaluateAll is deterministic", () => {
    const ctx = {
      pageOrigin: "https://evil.example/",
      pageRoot: "evil.example",
      forms: [{ action: "https://evil-collector.cc/grab", hasPassword: true }],
      visibleText: "Sign in to Microsoft Office 365",
      title: "Microsoft Sign in",
    };
    const a = evaluateAll(ctx);
    const b = evaluateAll(ctx);
    expect(a).toEqual(b);
  });
  it("external-form-post fires on cross-root POST", () => {
    const r = RULES_BY_ID["external-form-post"].evaluate({
      pageOrigin: "https://a.example/", pageRoot: "a.example",
      forms: [{ action: "https://b.example/x", hasPassword: true }],
    });
    expect(r.matched).toBe(true);
    expect(r.contribution).toBeLessThan(0);
  });
  it("safelisted-root contributes trust", () => {
    const r = RULES_BY_ID["safelisted-root"].evaluate({ pageRoot: "google.com" });
    expect(r.matched).toBe(true);
    expect(r.contribution).toBeGreaterThan(0);
  });
  it("rules never throw on missing context", () => {
    for (const r of RULES) {
      expect(() => r.evaluate({})).not.toThrow();
    }
  });
});
