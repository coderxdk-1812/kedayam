import { describe, it, expect } from "vitest";
import { BLOCKLIST_SNAPSHOT } from "../../extension/lib/rules/blocklistSnapshot.js";
import { matchBlocklist } from "../../extension/lib/threatFeed.js";

describe("bundled threat-feed snapshot", () => {
  it("bakes thousands of hosts into the signed bundle for day-one coverage", () => {
    expect(Array.isArray(BLOCKLIST_SNAPSHOT)).toBe(true);
    expect(BLOCKLIST_SNAPSHOT.length).toBeGreaterThan(1000);
  });

  it("is frozen and contains only bare lowercase hosts (no scheme/path)", () => {
    expect(Object.isFrozen(BLOCKLIST_SNAPSHOT)).toBe(true);
    for (const h of BLOCKLIST_SNAPSHOT.slice(0, 200)) {
      expect(h).toBe(h.toLowerCase());
      expect(h).not.toMatch(/^https?:|\/|\s/);
      expect(h).toContain(".");
    }
  });

  it("matchBlocklist() flags a host drawn from the snapshot as bundled", () => {
    // Sample a few entries so the test is robust to the feed changing over time.
    for (const host of [BLOCKLIST_SNAPSHOT[0], BLOCKLIST_SNAPSHOT[BLOCKLIST_SNAPSHOT.length - 1]]) {
      const r = matchBlocklist(host);
      expect(r.match).toBe(true);
      expect(r.source).toBe("bundled");
    }
  });

  it("does not flag an obviously clean host", () => {
    expect(matchBlocklist("github.com").match).toBe(false);
    expect(matchBlocklist("google.com").match).toBe(false);
  });
});
