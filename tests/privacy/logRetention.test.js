// Phase R4 — activity log retention / privacy hygiene.
//
// Uses an in-memory shim for chrome.storage.local so the test runs in pure
// Node and never touches real extension storage.

import { describe, it, expect, beforeEach } from "vitest";

// Minimal chrome.storage.local shim.
function installStorageShim() {
  const data = new Map();
  globalThis.chrome = {
    storage: {
      local: {
        get: async (key) => {
          if (key == null) {
            const out = {};
            for (const [k, v] of data) out[k] = v;
            return out;
          }
          if (Array.isArray(key)) {
            const out = {};
            for (const k of key) if (data.has(k)) out[k] = data.get(k);
            return out;
          }
          if (typeof key === "string") {
            return data.has(key) ? { [key]: data.get(key) } : {};
          }
          return {};
        },
        set: async (obj) => { for (const [k, v] of Object.entries(obj)) data.set(k, v); },
        remove: async (keys) => {
          const arr = Array.isArray(keys) ? keys : [keys];
          for (const k of arr) data.delete(k);
        },
      },
      session: { get: async () => ({}), set: async () => {} },
    },
  };
  return data;
}

let store;
let mod;
beforeEach(async () => {
  store = installStorageShim();
  // Force re-import each test to start clean.
  mod = await import("../../extension/lib/storage.js?cachebust=" + Math.random());
});

describe("R4 — activity log TTL + ring buffer", () => {
  it("entries older than ACTIVITY_TTL_MS are dropped on read", async () => {
    const KEY = "kedayam:v1:activity";
    const fresh = { kind: "trust", host: "a.test", at: Date.now() };
    const old   = { kind: "trust", host: "b.test", at: Date.now() - mod.ACTIVITY_TTL_MS - 1000 };
    store.set(KEY, [fresh, old]);
    const out = await mod.getActivity();
    expect(out.map((e) => e.host)).toEqual(["a.test"]);
  });

  it("appendActivity prunes expired entries before inserting", async () => {
    const KEY = "kedayam:v1:activity";
    store.set(KEY, [{ kind: "trust", host: "old.test", at: Date.now() - mod.ACTIVITY_TTL_MS - 1 }]);
    await mod.appendActivity({ kind: "trust", host: "new.test" });
    const persisted = store.get(KEY);
    expect(persisted.find((e) => e.host === "old.test")).toBeUndefined();
    expect(persisted.find((e) => e.host === "new.test")).toBeTruthy();
  });

  it("ring-buffer bound is enforced", async () => {
    for (let i = 0; i < mod.ACTIVITY_MAX + 50; i++) {
      await mod.appendActivity({ kind: "trust", host: `h${i}.test` });
    }
    const list = await mod.getActivity();
    expect(list.length).toBeLessThanOrEqual(mod.ACTIVITY_MAX);
  });

  it("sweepExpiredActivity removes expired entries deterministically", async () => {
    const KEY = "kedayam:v1:activity";
    const now = Date.now();
    store.set(KEY, [
      { kind: "trust", host: "k1", at: now },
      { kind: "trust", host: "k2", at: now - mod.ACTIVITY_TTL_MS - 10 },
      { kind: "trust", host: "k3", at: now - mod.ACTIVITY_TTL_MS - 100000 },
    ]);
    const r = await mod.sweepExpiredActivity();
    expect(r.kept).toBe(1);
    expect(r.removed).toBe(2);
  });

  it("strips fields not in the allowlist (no sensitive payload retention)", async () => {
    await mod.appendActivity({
      kind: "trust", host: "x.test", score: 50, status: "suspicious",
      // Forbidden fields — must NEVER persist.
      password: "hunter2",
      clipboard: "card number",
      rawHtml: "<form>...</form>",
      cookie: "session=abc",
    });
    const list = await mod.getActivity();
    const e = list[0];
    expect(e.password).toBeUndefined();
    expect(e.clipboard).toBeUndefined();
    expect(e.rawHtml).toBeUndefined();
    expect(e.cookie).toBeUndefined();
    expect(e.host).toBe("x.test");
    expect(e.score).toBe(50);
  });

  it("rejects non-object entries silently", async () => {
    await mod.appendActivity(null);
    await mod.appendActivity("hello");
    await mod.appendActivity(42);
    const list = await mod.getActivity();
    expect(list.length).toBe(0);
  });
});
