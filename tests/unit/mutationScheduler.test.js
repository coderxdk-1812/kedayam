// Verifies the throttling primitives that protect against scan storms.
import { describe, it, expect, vi } from "vitest";
import { Budget, debounce, throttle, idle } from "../../extension/lib/scheduler.js";

describe("Budget token bucket", () => {
  it("allows up to max within a window then drops", () => {
    const b = new Budget({ max: 3, windowMs: 100 });
    expect(b.allow()).toBe(true);
    expect(b.allow()).toBe(true);
    expect(b.allow()).toBe(true);
    expect(b.allow()).toBe(false);
  });

  it("recovers tokens after the window elapses", async () => {
    const b = new Budget({ max: 2, windowMs: 30 });
    b.allow();
    b.allow();
    expect(b.allow()).toBe(false);
    await new Promise((r) => setTimeout(r, 45));
    expect(b.allow()).toBe(true);
  });
});

describe("debounce", () => {
  it("coalesces rapid calls into a single trailing invocation", async () => {
    const fn = vi.fn();
    const d = debounce(fn, 20);
    for (let i = 0; i < 10; i++) d(i);
    await new Promise((r) => setTimeout(r, 40));
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn).toHaveBeenLastCalledWith(9);
  });
});

describe("throttle", () => {
  it("invokes leading and trailing only, never every call", async () => {
    const fn = vi.fn();
    const t = throttle(fn, 30);
    t(1);
    t(2);
    t(3);
    await new Promise((r) => setTimeout(r, 50));
    t(4);
    expect(fn.mock.calls.length).toBeLessThanOrEqual(3);
    expect(fn.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});

describe("idle", () => {
  it("falls back to setTimeout when requestIdleCallback is missing", async () => {
    expect(typeof globalThis.requestIdleCallback).toBe("undefined");
    const fn = vi.fn();
    idle(fn, 50);
    await new Promise((r) => setTimeout(r, 5));
    expect(fn).toHaveBeenCalled();
  });
});
