import { describe, it, expect } from "vitest";
import { evaluateAll, RULES, RULES_BY_CATEGORY, REGISTRY_VERSION } from "../../extension/lib/rules/index.js";

describe("expanded rule registry (M4)", () => {
  it("registry version bumped and frozen", () => {
    expect(REGISTRY_VERSION).toBeGreaterThanOrEqual(2);
    expect(Object.isFrozen(RULES)).toBe(true);
  });
  it("indexes by category — behavioral + antiEvasion present", () => {
    expect(RULES_BY_CATEGORY.behavioral?.length).toBeGreaterThanOrEqual(3);
    expect(RULES_BY_CATEGORY.antiEvasion?.length).toBeGreaterThanOrEqual(1);
  });
  it("behavioral rules fire from authFlow anomalies", () => {
    const ctx = { authFlow: { anomalies: [
      { id: "credential-relay",   explain: "to evil" },
      { id: "oauth-token-drift",  explain: "drift"   },
      { id: "iframe-origin-swap", explain: "iframe"  },
    ] } };
    const results = evaluateAll(ctx);
    const fired = results.filter((r) => r.matched).map((r) => r.id);
    expect(fired).toContain("credential-relay");
    expect(fired).toContain("oauth-token-drift");
    expect(fired).toContain("iframe-origin-swap");
  });
  it("csp-downgrade only fires when credentials are present and CSP was checked", () => {
    const r1 = evaluateAll({ hasAuthWorkflow: true, cspChecked: true, cspPresent: false });
    expect(r1.find((x) => x.id === "csp-downgrade").matched).toBe(true);
    const r2 = evaluateAll({ hasAuthWorkflow: true, cspChecked: false, cspPresent: false });
    expect(r2.find((x) => x.id === "csp-downgrade").matched).toBe(false);
    const r3 = evaluateAll({ hasAuthWorkflow: false, cspChecked: true, cspPresent: false });
    expect(r3.find((x) => x.id === "csp-downgrade").matched).toBe(false);
  });
});
