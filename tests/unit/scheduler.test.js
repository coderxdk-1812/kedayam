import { describe, it, expect, vi } from "vitest";
import { debounce, throttle, Budget, idle } from "../../extension/lib/scheduler.js";

describe("debounce", () => {
  it("collapses rapid calls into one", () => {
    vi.useFakeTimers();
    const fn = vi.fn();
    const d = debounce(fn, 50);
    d(); d(); d();
    expect(fn).not.toHaveBeenCalled();
    vi.advanceTimersByTime(60);
    expect(fn).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });
});

describe("throttle", () => {
  it("runs immediately and caps subsequent calls", () => {
    vi.useFakeTimers();
    const fn = vi.fn();
    const t = throttle(fn, 100);
    t("a"); t("b"); t("c");
    expect(fn).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(120);
    expect(fn).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });
});

describe("Budget", () => {
  it("permits up to max in window then blocks", () => {
    const b = new Budget({ max: 3, windowMs: 1000 });
    expect(b.allow()).toBe(true);
    expect(b.allow()).toBe(true);
    expect(b.allow()).toBe(true);
    expect(b.allow()).toBe(false);
  });
});

describe("idle", () => {
  it("eventually invokes the callback", async () => {
    await new Promise((res) => idle(() => res(true), 200));
  });
});