import { describe, it, expect } from "vitest";
import { migrate, isEnabled, SCHEMA_VERSION, FEATURE_FLAGS } from "../../extension/lib/featureFlags.js";

describe("featureFlags", () => {
  it("migrate stamps the current schema version", () => {
    const out = migrate({});
    expect(out.schemaVersion).toBe(SCHEMA_VERSION);
  });
  it("migrate preserves user settings", () => {
    const out = migrate({ allowlist: ["a.example"] });
    expect(out.allowlist).toEqual(["a.example"]);
  });
  it("migrate populates feature defaults at v3", () => {
    const out = migrate({ schemaVersion: 2 });
    expect(out.features).toBeDefined();
    expect(out.features.phishingHeuristics).toBe(true);
    expect(out.features.debugMode).toBe(false);
  });
  it("migrate is idempotent", () => {
    const a = migrate({});
    const b = migrate(a);
    expect(b).toEqual(a);
  });
  it("FEATURE_FLAGS is frozen", () => {
    expect(Object.isFrozen(FEATURE_FLAGS)).toBe(true);
  });
  it("isEnabled honors overrides", () => {
    expect(isEnabled("debugMode")).toBe(false);
    expect(isEnabled("debugMode", { debugMode: true })).toBe(true);
  });
});
