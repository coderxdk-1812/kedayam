import { describe, it, expect } from "vitest";
import {
  PROTECTION_CATALOG,
  PROTECTION_LIMITS,
  getProtectionOverview,
  protectionSummary,
} from "../../extension/lib/protectionCatalog.js";

describe("protectionCatalog", () => {
  it("is frozen and every entry is well-formed", () => {
    expect(Object.isFrozen(PROTECTION_CATALOG)).toBe(true);
    const ratings = new Set(["HIGH", "MED", "LOW"]);
    for (const p of PROTECTION_CATALOG) {
      expect(typeof p.id).toBe("string");
      expect(p.title && p.what && p.limit).toBeTruthy();
      expect(ratings.has(p.upliftRating)).toBe(true);
      expect(typeof p.defaultOn).toBe("boolean");
      // settingsPath is either null (core) or a dotted string
      expect(p.settingsPath === null || typeof p.settingsPath === "string").toBe(true);
    }
  });

  it("has unique ids", () => {
    const ids = PROTECTION_CATALOG.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("keeps the honest limits list non-empty", () => {
    expect(PROTECTION_LIMITS.length).toBeGreaterThan(0);
    expect(PROTECTION_LIMITS.join(" ")).toMatch(/Safe Browsing/);
  });

  it("marks the two flagship gaps as HIGH uplift", () => {
    const high = PROTECTION_CATALOG.filter((p) => p.upliftRating === "HIGH").map((p) => p.id);
    expect(high).toContain("clickfix");
    expect(high).toContain("data-leak");
  });
});

describe("getProtectionOverview", () => {
  it("treats core (no settingsPath) layers as always on", () => {
    const rows = getProtectionOverview(null);
    const core = rows.filter((r) => r.core);
    expect(core.length).toBeGreaterThan(0);
    expect(core.every((r) => r.enabled === true)).toBe(true);
  });

  it("reflects a toggled-off setting as disabled", () => {
    const rows = getProtectionOverview({ detection: { clickFixGuard: false } });
    const cf = rows.find((r) => r.id === "clickfix");
    expect(cf.enabled).toBe(false);
  });

  it("falls back to defaultOn when the setting is absent", () => {
    const rows = getProtectionOverview({});
    const bl = rows.find((r) => r.id === "blocklist");
    expect(bl.enabled).toBe(true); // defaultOn
  });
});

describe("protectionSummary", () => {
  it("counts active and HIGH-uplift layers", () => {
    const all = protectionSummary({});
    expect(all.total).toBe(PROTECTION_CATALOG.length);
    expect(all.active).toBe(all.total); // all default-on
    expect(all.highActive).toBeGreaterThanOrEqual(2);

    const off = protectionSummary({
      detection: { clickFixGuard: false, pasteInterception: false },
    });
    expect(off.highActive).toBe(0);
    expect(off.active).toBe(all.total - 2);
  });
});
