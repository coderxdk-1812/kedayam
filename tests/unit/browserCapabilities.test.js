import { describe, it, expect } from "vitest";
import { detectCapabilities, withCapabilities, _resetCapabilities } from "../../extension/lib/browserCapabilities.js";

describe("browserCapabilities", () => {
  beforeEach(() => _resetCapabilities());

  it("returns a frozen snapshot with boolean fields", () => {
    const c = detectCapabilities({});
    expect(Object.isFrozen(c)).toBe(true);
    for (const v of Object.values(c)) expect(typeof v).toBe("boolean");
  });

  it("withCapabilities falls back when capability is missing", () => {
    const out = withCapabilities(["nonexistent"], () => "ran", "fallback");
    expect(out).toBe("fallback");
  });

  it("withCapabilities swallows callback errors silently", () => {
    // Provide a fake global that has the capability flag.
    _resetCapabilities();
    const fake = { ShadowRoot: function () {} };
    detectCapabilities(fake);
    const out = withCapabilities(["shadowDom"], () => { throw new Error("x"); }, "ok");
    expect(out).toBe("ok");
  });

  it("detects MutationObserver / IntersectionObserver in jsdom", () => {
    const c = detectCapabilities();
    expect(typeof c.mutationObserver).toBe("boolean");
  });
});

// Vitest globals
import { beforeEach } from "vitest";
