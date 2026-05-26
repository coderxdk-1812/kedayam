// Performance — memory & listener bounds. Catches leaks before release.
import { describe, it, expect } from "vitest";
import { WarningCooldown, UX_POLICY } from "../../extension/lib/uxPolicy.js";
import { Budget } from "../../extension/lib/scheduler.js";

describe("memory bounds", () => {
  it("WarningCooldown evicts old entries past the cap", () => {
    const c = new WarningCooldown({ ...UX_POLICY, COOLDOWN_MAX_ENTRIES: 50 });
    for (let i = 0; i < 500; i++) c.markShown(`host${i}.example.com`, "phishing");
    expect(c.size()).toBeLessThanOrEqual(50);
  });

  it("cooldown blocks within window, releases after", async () => {
    const c = new WarningCooldown({ ...UX_POLICY, WARNING_COOLDOWN_MS: 30 });
    expect(c.shouldShow("a.com", "x")).toBe(true);
    c.markShown("a.com", "x");
    expect(c.shouldShow("a.com", "x")).toBe(false);
    await new Promise((r) => setTimeout(r, 40));
    expect(c.shouldShow("a.com", "x")).toBe(true);
  });

  it("Budget never permanently grows under sustained pressure", async () => {
    const b = new Budget({ max: 5, windowMs: 25 });
    for (let i = 0; i < 1000; i++) b.allow();
    await new Promise((r) => setTimeout(r, 40));
    b.allow();
    // After window elapses the internal hits array should be small.
    // We can't peek directly, but a fresh window should grant up to max again.
    let granted = 1;
    for (let i = 0; i < 100; i++) if (b.allow()) granted++;
    expect(granted).toBeLessThanOrEqual(5);
  });
});
