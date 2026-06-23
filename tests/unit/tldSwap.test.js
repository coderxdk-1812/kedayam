import { describe, it, expect } from "vitest";
import { analyzeUrlReputation } from "../../extension/lib/urlReputation.js";

describe("TLD-swap detection", () => {
  it("flags the brand name on the wrong TLD", () => {
    const r = analyzeUrlReputation("https://paypal.co/login", { hasAuthWorkflow: true });
    expect(r.tldSwap).not.toBeNull();
    expect(r.tldSwap.brand).toBe("paypal.com");
    expect(r.signals.some((s) => s.id === "tld-swap")).toBe(true);
    expect(r.cap).toBeLessThanOrEqual(45);
  });

  it("flags apple on a different TLD", () => {
    const r = analyzeUrlReputation("https://apple.org/");
    expect(r.tldSwap?.brand).toBe("apple.com");
  });

  it("does NOT flag the genuine brand domain", () => {
    expect(analyzeUrlReputation("https://www.paypal.com/").tldSwap).toBeNull();
    expect(analyzeUrlReputation("https://apple.com/").tldSwap).toBeNull();
  });

  it("does NOT treat a hyphen combosquat as a TLD swap (exact SLD only)", () => {
    // paypal-secure.com has SLD "paypal-secure", not "paypal".
    expect(analyzeUrlReputation("https://paypal-secure.com/").tldSwap).toBeNull();
  });

  it("is suppressed on a trusted root", () => {
    expect(analyzeUrlReputation("https://paypal.co/", { isTrustedRoot: true }).tldSwap).toBeNull();
  });
});
