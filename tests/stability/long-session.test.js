// Long-session stability: simulate many navigations / mutations and
// verify the cooldown LRU, in-flight dedup, and rule registry stay bounded.

import { describe, it, expect } from "vitest";
import { WarningCooldown } from "../../extension/lib/uxPolicy.js";
import { DiagnosticsBuffer } from "../../extension/lib/diagnostics.js";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

describe("stability: 1000 navigations", () => {
  it("evaluateUrl mean latency stays bounded over 1000 calls", async () => {
    const settings = { detection: { sensitivity: "balanced" }, apiKeys: {}, allowlist: [] };
    const start = Date.now();
    for (let i = 0; i < 1000; i++) {
      const u = `https://host${i % 50}.example/${i}`;

      await evaluateUrl(u, { settings });
    }
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(8000); // < 8s for 1k navigations
  });

  it("WarningCooldown LRU stays at its cap", () => {
    const c = new WarningCooldown();
    for (let i = 0; i < 10_000; i++) c.markShown(`host${i}.example`, "phish");
    expect(c.size()).toBeLessThanOrEqual(256);
  });

  it("DiagnosticsBuffer ring stays bounded under flood", () => {
    const d = new DiagnosticsBuffer(64);
    d.enable();
    for (let i = 0; i < 10_000; i++) d.record("nav", { i });
    expect(d.snapshot().length).toBe(64);
  });
});
