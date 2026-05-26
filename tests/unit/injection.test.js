import { describe, it, expect } from "vitest";
import { isInjectableUrl, reasonForSkip, InjectionRegistry, ensureInjected } from "../../extension/lib/injection.js";

describe("isInjectableUrl", () => {
  it("allows http and https", () => {
    expect(isInjectableUrl("https://example.com/")).toBe(true);
    expect(isInjectableUrl("http://example.com/")).toBe(true);
  });
  it("blocks chrome:// and other browser-internal pages", () => {
    expect(isInjectableUrl("chrome://settings/")).toBe(false);
    expect(isInjectableUrl("edge://flags")).toBe(false);
    expect(isInjectableUrl("about:blank")).toBe(false);
    expect(isInjectableUrl("devtools://devtools/bundled/devtools_app.html")).toBe(false);
  });
  it("blocks the Chrome Web Store", () => {
    expect(isInjectableUrl("https://chrome.google.com/webstore")).toBe(false);
    expect(isInjectableUrl("https://chromewebstore.google.com/")).toBe(false);
  });
  it("blocks chrome-extension:// and view-source:", () => {
    expect(isInjectableUrl("chrome-extension://abc/popup.html")).toBe(false);
    expect(isInjectableUrl("view-source:https://example.com")).toBe(false);
  });
  it("returns false for invalid URLs", () => {
    expect(isInjectableUrl("")).toBe(false);
    expect(isInjectableUrl("not a url")).toBe(false);
    expect(isInjectableUrl(null)).toBe(false);
  });
  it("reasonForSkip explains why", () => {
    expect(reasonForSkip("chrome://settings")).toMatch(/protocol/);
    expect(reasonForSkip("https://chromewebstore.google.com/")).toMatch(/host/);
  });
});

describe("InjectionRegistry", () => {
  it("tracks per-tab url and dedupes", () => {
    const r = new InjectionRegistry();
    expect(r.has(1, "https://a/")).toBe(false);
    r.mark(1, "https://a/");
    expect(r.has(1, "https://a/")).toBe(true);
    expect(r.has(1, "https://b/")).toBe(false);
    r.clear(1);
    expect(r.has(1, "https://a/")).toBe(false);
  });
  it("prunes old entries", () => {
    const r = new InjectionRegistry();
    r.mark(1, "https://a/");
    r.tabs.get(1).at = Date.now() - 10 * 60 * 60 * 1000;
    r.prune(60 * 1000);
    expect(r.has(1, "https://a/")).toBe(false);
  });
});

describe("ensureInjected", () => {
  it("skips non-injectable urls without calling chrome.scripting", async () => {
    let called = false;
    const scripting = { executeScript: async () => { called = true; } };
    const r = new InjectionRegistry();
    const out = await ensureInjected(1, "chrome://settings/", r, scripting);
    expect(out.injected).toBe(false);
    expect(called).toBe(false);
  });
  it("injects once per tab+url", async () => {
    let calls = 0;
    const scripting = { executeScript: async () => { calls++; } };
    const r = new InjectionRegistry();
    await ensureInjected(1, "https://a/", r, scripting);
    await ensureInjected(1, "https://a/", r, scripting);
    expect(calls).toBe(1);
  });
  it("re-injects when url changes for the same tab", async () => {
    let calls = 0;
    const scripting = { executeScript: async () => { calls++; } };
    const r = new InjectionRegistry();
    await ensureInjected(1, "https://a/", r, scripting);
    await ensureInjected(1, "https://b/", r, scripting);
    expect(calls).toBe(2);
  });
  it("reports injection errors gracefully", async () => {
    const scripting = { executeScript: async () => { throw new Error("boom"); } };
    const r = new InjectionRegistry();
    const out = await ensureInjected(1, "https://a/", r, scripting);
    expect(out.injected).toBe(false);
    expect(out.reason).toMatch(/boom/);
  });
});
