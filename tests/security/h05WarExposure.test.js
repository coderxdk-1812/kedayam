// H-05 — WAR shim exposure: regression coverage.
//
// DECISION: The MAIN-world shim is intentionally retained.
//
// Why we cannot remove it without increasing risk:
//   * Permission monitoring (camera, mic, geolocation, clipboard) requires
//     hooking navigator.* on the page's MAIN world. Content scripts run in
//     an isolated world and cannot override page-visible globals.
//   * The MV3-native alternative — chrome.scripting.executeScript({ world:
//     "MAIN" }) — requires the "scripting" permission. The manifest review
//     (see tests/security/isolationHardening.test.js) explicitly forbids
//     "scripting" because it widens the privileged surface dramatically.
//   * Inline <script> injection is blocked by strict page CSPs and would
//     silently break monitoring on the very sites (banks, IdPs) where it
//     matters most.
//   * Removing the feature would reduce detection coverage with no
//     compensating gain.
//
// The exposure is mitigated by:
//   1. Exactly one WAR entry, pointing at one auditable file.
//   2. use_dynamic_url=true — the path rotates per session, defeating
//      stable fingerprint probes.
//   3. matches restricted to http/https (no all_urls, no extension URLs).
//   4. The shim itself contains no extension internals, no secrets, no
//      message bus surface — only navigator.* hooks that post a CustomEvent
//      observable to the page anyway.
//
// These regression tests lock the mitigation in place and prevent future
// exposure creep (extra WAR entries, leaked internals, broadened matches).

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "../..");
const manifest = JSON.parse(readFileSync(resolve(root, "extension/manifest.json"), "utf8"));
const shimSrc = readFileSync(resolve(root, "extension/content/main-world-shim.js"), "utf8");

describe("H-05 — WAR shim exposure (intentionally retained, mitigation locked)", () => {
  it("manifest exposes exactly one WAR entry", () => {
    expect(Array.isArray(manifest.web_accessible_resources)).toBe(true);
    expect(manifest.web_accessible_resources).toHaveLength(1);
  });

  it("WAR exposes only the MAIN-world shim — no other files", () => {
    const entry = manifest.web_accessible_resources[0];
    expect(entry.resources).toEqual(["content/main-world-shim.js"]);
  });

  it("use_dynamic_url is enabled to defeat stable fingerprinting", () => {
    expect(manifest.web_accessible_resources[0].use_dynamic_url).toBe(true);
  });

  it("WAR matches are restricted to http/https (no <all_urls>, no extension URLs)", () => {
    const m = manifest.web_accessible_resources[0].matches;
    expect(m).toEqual(["http://*/*", "https://*/*"]);
    expect(m).not.toContain("<all_urls>");
    expect(m.some((s) => s.startsWith("chrome-extension://"))).toBe(false);
  });

  it("does NOT request the 'scripting' permission — keeps WAR shim as the only injection path", () => {
    // Switching to chrome.scripting.executeScript({world:"MAIN"}) would
    // remove the WAR entry but require "scripting", widening the
    // privileged surface. The trade-off is rejected.
    expect(manifest.permissions).not.toContain("scripting");
  });

  it("shim contents do not leak extension internals", () => {
    // Anything the page can read about the extension increases
    // fingerprintability. The shim must not reference message bus types,
    // storage keys, runtime ids, or other internal identifiers.
    const forbidden = [
      "chrome.runtime",
      "chrome.storage",
      "chrome.tabs",
      "messageSchemas",
      "trustEngine",
      "sensitiveData",
      "kedayam-test-extension-id",
    ];
    for (const needle of forbidden) {
      expect(shimSrc).not.toContain(needle);
    }
  });

  it("shim only hooks navigator.* APIs and posts a CustomEvent (no other surface)", () => {
    // Lock the shape: any new capability added to the shim must be
    // reviewed against H-05. Tests fail loudly if the shim grows.
    expect(shimSrc).toMatch(/navigator\.mediaDevices/);
    expect(shimSrc).toMatch(/navigator\.geolocation/);
    expect(shimSrc).toMatch(/navigator\.clipboard/);
    expect(shimSrc).toMatch(/new CustomEvent\(["']kedayam:perm["']/);
    // Outbound channels other than the documented CustomEvent are forbidden.
    expect(shimSrc).not.toMatch(/postMessage\s*\(/);
    expect(shimSrc).not.toMatch(/\bfetch\s*\(/);
    expect(shimSrc).not.toMatch(/XMLHttpRequest/);
    expect(shimSrc).not.toMatch(/WebSocket/);
    expect(shimSrc).not.toMatch(/navigator\.sendBeacon/);
  });

  it("shim remains small and auditable (< 6 KB)", () => {
    // A small upper bound catches accidental bloat and discourages adding logic
    // that belongs in the isolated-world content script. Raised from 4 KB when
    // the ClickFix hardening added the deferred-write hooks (clipboard.write /
    // DataTransfer.setData) — which MUST live in the main world to hook page APIs.
    expect(shimSrc.length).toBeLessThan(6144);
  });

  it("shim self-guards against double-injection", () => {
    expect(shimSrc).toMatch(/__kedayamShim/);
  });
});
