import { describe, it, expect } from "vitest";
import {
  validatePolicy,
  exportSettings,
  importSettings,
  readManagedPolicy,
} from "../../extension/lib/managedPolicy.js";

describe("managedPolicy", () => {
  it("validatePolicy returns null on garbage", () => {
    expect(validatePolicy(null)).toBeNull();
    expect(validatePolicy(123)).toBeNull();
    expect(validatePolicy({})).toBeNull();
    expect(validatePolicy({ unknown: 1 })).toBeNull();
  });
  it("validatePolicy keeps only allowed keys", () => {
    const p = validatePolicy({
      allowlist: ["a.example", "b.example", 5, "x".repeat(300)],
      denylist: ["bad.example"],
      sensitivity: "strict",
      debugMode: true,
      bogus: "drop me",
    });
    expect(p.allowlist).toEqual(["a.example", "b.example"]);
    expect(p.denylist).toEqual(["bad.example"]);
    expect(p.sensitivity).toBe("strict");
    expect(p.debugMode).toBe(true);
    expect(p.bogus).toBeUndefined();
  });
  it("validatePolicy rejects bad sensitivity values", () => {
    expect(validatePolicy({ sensitivity: "extreme" })).toBeNull();
  });
  it("export then import is round-trip stable", () => {
    const settings = {
      schemaVersion: 3,
      detection: { sensitivity: "balanced" },
      allowlist: ["a.example"],
      features: { debugMode: false },
      // these should be stripped from export
      cache: { secret: 1 },
      activity: [{ url: "https://x" }],
    };
    const exported = exportSettings(settings);
    expect(exported.cache).toBeUndefined();
    expect(exported.activity).toBeUndefined();
    const imported = importSettings(exported);
    expect(imported.schemaVersion).toBe(3);
    expect(imported.allowlist).toEqual(["a.example"]);
  });
  it("readManagedPolicy returns null when storage absent", async () => {
    expect(await readManagedPolicy(null)).toBeNull();
  });
  it("readManagedPolicy reads via callback API", async () => {
    const fake = { get: (_keys, cb) => cb({ sensitivity: "lenient" }) };
    const r = await readManagedPolicy(fake);
    expect(r?.sensitivity).toBe("lenient");
  });
});
