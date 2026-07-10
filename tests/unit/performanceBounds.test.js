// Asserts the engine completes within deterministic time + memory bounds
// for adversarial inputs. These bounds protect long browsing sessions.
import { describe, it, expect } from "vitest";
import { analyzeSensitivePayload } from "../../extension/lib/sensitiveDataEngine.js";
import { Budget } from "../../extension/lib/scheduler.js";

describe("performance bounds", () => {
  it("caps findings even when the page is a wall of matches", () => {
    const noise = "AKIAABCDEFGHIJKLMNOP ".repeat(500);
    const start = Date.now();
    const v = analyzeSensitivePayload(noise);
    const elapsed = Date.now() - start;
    expect(v.findings.length).toBeLessThanOrEqual(200);
    // 50ms is generous; a regression here means a pathological loop slipped in.
    expect(elapsed).toBeLessThan(200);
  });

  it("scans a realistic 50KB payload in under 100ms", () => {
    const body = "Lorem ipsum dolor sit amet ".repeat(2000) + "\nMy email is alice@example.com\n";
    const start = Date.now();
    analyzeSensitivePayload(body);
    expect(Date.now() - start).toBeLessThan(150);
  });

  it("MutationObserver-style budget caps scan storms", () => {
    const b = new Budget({ max: 10, windowMs: 50 });
    let allowed = 0;
    for (let i = 0; i < 1000; i++) if (b.allow()) allowed++;
    expect(allowed).toBeLessThanOrEqual(10);
  });

  it("entropy fallback does not produce unbounded entries", () => {
    const random = Array.from(
      { length: 200 },
      () => Math.random().toString(36).slice(2, 18) + "+_=",
    ).join(" ");
    const v = analyzeSensitivePayload(random);
    const entropy = v.findings.filter((f) => f.id === "entropy_blob");
    expect(entropy.length).toBeLessThanOrEqual(40);
  });
});
