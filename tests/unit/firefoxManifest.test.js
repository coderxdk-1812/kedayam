import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { toFirefoxManifest } from "../../scripts/lib/firefoxManifest.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const chrome = JSON.parse(
  readFileSync(path.resolve(__dirname, "../../extension/manifest.json"), "utf8"),
);

describe("toFirefoxManifest", () => {
  const ff = toFirefoxManifest(chrome);

  it("adds a Gecko id and min version", () => {
    expect(ff.browser_specific_settings.gecko.id).toContain("@");
    expect(ff.browser_specific_settings.gecko.strict_min_version).toMatch(/^\d+\.\d+$/);
  });

  it("converts the service worker to an event-page background script (ESM)", () => {
    expect(ff.background.service_worker).toBeUndefined();
    expect(ff.background.scripts).toEqual(["background.js"]);
    expect(ff.background.type).toBe("module");
  });

  it("drops Chrome-only keys", () => {
    expect(ff.minimum_chrome_version).toBeUndefined();
  });

  it("strips use_dynamic_url from web_accessible_resources", () => {
    for (const war of ff.web_accessible_resources || []) {
      expect(war.use_dynamic_url).toBeUndefined();
      expect(Array.isArray(war.resources)).toBe(true);
    }
  });

  it("preserves core fields and does not mutate the input", () => {
    expect(ff.manifest_version).toBe(3);
    expect(ff.name).toBe(chrome.name);
    expect(ff.permissions).toEqual(chrome.permissions);
    // input untouched
    expect(chrome.background.service_worker).toBe("background.js");
    expect(chrome.minimum_chrome_version).toBeDefined();
  });
});
