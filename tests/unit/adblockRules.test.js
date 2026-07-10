import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { domainsToDnrRules, normalizeDomain } from "../../scripts/lib/adblockRules.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ruleset = JSON.parse(
  readFileSync(path.resolve(__dirname, "../../extension/rules/adblock-rules.json"), "utf8"),
);

describe("normalizeDomain", () => {
  it("cleans hosts-file / ABP / www forms", () => {
    expect(normalizeDomain("0.0.0.0 ads.example.com")).toBe("ads.example.com");
    expect(normalizeDomain("||track.example.com^")).toBe("track.example.com");
    expect(normalizeDomain("www.Ads.Example.com")).toBe("ads.example.com");
  });
  it("rejects comments and non-hosts", () => {
    expect(normalizeDomain("# comment")).toBe("");
    expect(normalizeDomain("localhost")).toBe("");
    expect(normalizeDomain("has space.com")).toBe("");
  });
});

describe("domainsToDnrRules", () => {
  it("packs domains into chunked block rules", () => {
    const domains = Array.from({ length: 2500 }, (_, i) => `t${i}.example`);
    const rules = domainsToDnrRules(domains, { chunkSize: 1000 });
    expect(rules.length).toBe(3);
    for (const r of rules) {
      expect(r.action.type).toBe("block");
      expect(r.condition.requestDomains.length).toBeLessThanOrEqual(1000);
      expect(r.id).toBeGreaterThan(0);
      // Never blocks the top-level document — only sub-resources.
      expect(r.condition.resourceTypes).not.toContain("main_frame");
    }
    // ids are unique
    expect(new Set(rules.map((r) => r.id)).size).toBe(rules.length);
  });
  it("dedupes and sorts deterministically", () => {
    const a = domainsToDnrRules(["b.com", "a.com", "b.com"]);
    expect(a[0].condition.requestDomains).toEqual(["a.com", "b.com"]);
  });
});

describe("shipped adblock ruleset", () => {
  it("bundles thousands of tracker domains as valid DNR block rules", () => {
    expect(Array.isArray(ruleset)).toBe(true);
    const total = ruleset.reduce((n, r) => n + r.condition.requestDomains.length, 0);
    expect(total).toBeGreaterThan(1000);
    for (const r of ruleset) {
      expect(r.action.type).toBe("block");
      expect(r.condition.resourceTypes).not.toContain("main_frame");
    }
  });
  it("does not block a reputable root", () => {
    const all = new Set(ruleset.flatMap((r) => r.condition.requestDomains));
    for (const good of ["google.com", "github.com", "wikipedia.org", "paypal.com"]) {
      expect(all.has(good)).toBe(false);
    }
  });
});
