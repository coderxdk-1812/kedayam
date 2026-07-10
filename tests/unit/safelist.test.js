import { describe, it, expect } from "vitest";
import {
  SAFELIST,
  SAFELIST_VERSION,
  isSafelistedRoot,
  safelistCategory,
} from "../../extension/lib/safelist.js";

describe("safelist", () => {
  it("is frozen and versioned", () => {
    expect(SAFELIST_VERSION).toBeGreaterThanOrEqual(1);
    expect(Object.isFrozen(SAFELIST)).toBe(true);
    expect(Object.isFrozen(SAFELIST.identityProviders)).toBe(true);
  });
  it("classifies known roots", () => {
    expect(isSafelistedRoot("google.com")).toBe(true);
    expect(isSafelistedRoot("paypal.com")).toBe(true);
    expect(isSafelistedRoot("evil.example")).toBe(false);
    expect(isSafelistedRoot("")).toBe(false);
    expect(safelistCategory("microsoft.com")).toBe("identity-provider");
    expect(safelistCategory("chase.com")).toBe("banking");
    expect(safelistCategory("1password.com")).toBe("password-manager");
    expect(safelistCategory("unknown.example")).toBeNull();
  });
});
