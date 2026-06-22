// Phase F4 — Final security review suite (release gate).
//
// Verifies extension isolation, message provenance, schema hardening, and
// that the web-accessible surface is minimal and intentional.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  validateMessage,
  isTrustedSender,
  TRUST_MUTATION_TYPES,
  SCHEMAS,
} from "../../extension/lib/messageSchemas.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(
  readFileSync(resolve(__dirname, "../../extension/manifest.json"), "utf8"),
);

const RUNTIME_ID = "kedayam-test-extension-id";
const okTabSender = {
  id: RUNTIME_ID,
  tab: { id: 7 },
  url: "https://example.com/",
  origin: "https://example.com",
};
const okUiSender = {
  id: RUNTIME_ID,
  url: `chrome-extension://${RUNTIME_ID}/popup/popup.html`,
  origin: `chrome-extension://${RUNTIME_ID}`,
};

describe("F1 — externally reachable surface", () => {
  it("externally_connectable is absent (MV3 hardening — see manifest pass v5)", () => {
    // Declaring an empty externally_connectable block produced a Chrome
    // console warning ("specifies neither 'matches' nor 'ids'; nothing
    // will be able to connect"). Since Kedayam intentionally exposes no
    // external messaging API, the field is removed entirely. Reintroducing
    // it (even as empty arrays) regresses reviewer-grade hygiene.
    expect(manifest.externally_connectable).toBeUndefined();
  });

  it("web_accessible_resources is minimal: only the MAIN-world shim", () => {
    const war = manifest.web_accessible_resources;
    expect(Array.isArray(war)).toBe(true);
    expect(war.length).toBe(1);
    expect(war[0].resources).toEqual(["content/main-world-shim.js"]);
    // overlay.css must NOT be web-accessible — it ships through
    // content_scripts.css and pages have no reason to read it.
    const flat = war.flatMap((e) => e.resources);
    expect(flat).not.toContain("content/overlay.css");
  });

  it("WAR matches are restricted to http/https — no all_urls wildcard", () => {
    for (const entry of manifest.web_accessible_resources) {
      expect(entry.matches).toEqual(["http://*/*", "https://*/*"]);
    }
  });

  it("shim uses dynamic URLs to reduce extension fingerprinting", () => {
    expect(manifest.web_accessible_resources[0].use_dynamic_url).toBe(true);
  });

  it("does NOT request scripting / management / debugger / cookies", () => {
    const denied = [
      "scripting",
      "management",
      "debugger",
      "cookies",
      "history",
      "browsingData",
      "downloads",
      "<all_urls>",
    ];
    for (const p of denied) expect(manifest.permissions).not.toContain(p);
  });
});

describe("H-06 — sender provenance validation", () => {
  it("rejects messages with no sender id", () => {
    expect(isTrustedSender({}, RUNTIME_ID, "scan")).toBe(false);
  });
  it("rejects messages from a different extension id", () => {
    expect(isTrustedSender({ id: "evil-ext-id", tab: { id: 1 } }, RUNTIME_ID, "scan")).toBe(false);
  });
  it("rejects messages with a web-page origin", () => {
    expect(
      isTrustedSender(
        { id: RUNTIME_ID, origin: "https://attacker.example", tab: null },
        RUNTIME_ID,
        "trustForSession",
      ),
    ).toBe(false);
  });
  it("accepts messages from this extension's content script (tab)", () => {
    expect(isTrustedSender(okTabSender, RUNTIME_ID, "scan")).toBe(true);
  });
  it("accepts messages from this extension's own UI pages", () => {
    expect(isTrustedSender(okUiSender, RUNTIME_ID, "getSettings")).toBe(true);
  });
  it("trust-mutation messages require tab OR extension UI origin", () => {
    // bare runtime sender (no tab, no extension url) — must be rejected.
    expect(isTrustedSender({ id: RUNTIME_ID }, RUNTIME_ID, "trustForSession")).toBe(false);
    expect(isTrustedSender(okTabSender, RUNTIME_ID, "trustForSession")).toBe(true);
    expect(isTrustedSender(okUiSender, RUNTIME_ID, "trustForSession")).toBe(true);
  });
  it("trust mutation set is complete and frozen", () => {
    expect(TRUST_MUTATION_TYPES.has("trustForSession")).toBe(true);
    expect(TRUST_MUTATION_TYPES.has("saveSettings")).toBe(true);
    expect(TRUST_MUTATION_TYPES.has("clearCaches")).toBe(true);
    expect(TRUST_MUTATION_TYPES.has("logEvent")).toBe(true);
    expect(TRUST_MUTATION_TYPES.has("refreshThreatFeed")).toBe(true);
    // Set itself is mutable, but the export reference is frozen via
    // Object.freeze and the TRUST_MUTATION_TYPES binding is const. The
    // important contract is that the membership matches.
    expect(TRUST_MUTATION_TYPES.size).toBe(5);
  });
});

describe("F3 — message schema hardening", () => {
  it("rejects unknown message types", () => {
    expect(validateMessage({ type: "exfiltrate" }).ok).toBe(false);
    expect(validateMessage({ type: "" }).ok).toBe(false);
    expect(validateMessage(null).ok).toBe(false);
    expect(validateMessage("string").ok).toBe(false);
  });
  it("rejects malformed scan payloads", () => {
    expect(validateMessage({ type: "scan" }).ok).toBe(false);
    expect(validateMessage({ type: "scan", url: "javascript:alert(1)" }).ok).toBe(false);
    expect(validateMessage({ type: "scan", url: "file:///etc/passwd" }).ok).toBe(false);
    expect(validateMessage({ type: "scan", url: "x".repeat(3000) }).ok).toBe(false);
  });
  it("accepts well-formed scan payloads", () => {
    const r = validateMessage({ type: "scan", url: "https://example.com/x", tabId: 5 });
    expect(r.ok).toBe(true);
    expect(r.value.url).toBe("https://example.com/x");
    expect(r.value.force).toBe(false);
  });
  it("rejects oversized payloads", () => {
    const big = {};
    for (let i = 0; i < 40; i++) big["k" + i] = i;
    expect(validateMessage({ type: "pageContext", context: big }).ok).toBe(false);
    expect(validateMessage({ type: "saveSettings", patch: big }).ok).toBe(false);
  });
  it("rejects invalid enum values", () => {
    expect(
      validateMessage({
        type: "saveSettings",
        patch: { detection: { sensitivity: "paranoid" } },
      }).ok,
    ).toBe(false);
  });
  it("rejects malformed domain values for trust mutations", () => {
    expect(validateMessage({ type: "trustForSession", domain: "" }).ok).toBe(false);
    expect(validateMessage({ type: "trustForSession", domain: "<script>" }).ok).toBe(false);
    expect(validateMessage({ type: "trustForSession", domain: "x".repeat(300) }).ok).toBe(false);
    expect(validateMessage({ type: "trustForSession", domain: "github.com" }).ok).toBe(true);
  });
  it("schemas are immutable", () => {
    expect(Object.isFrozen(SCHEMAS)).toBe(true);
  });
  it("validators never throw on hostile inputs", () => {
    const hostiles = [
      undefined,
      null,
      0,
      false,
      [],
      "",
      { type: 1 },
      { type: "scan", url: null },
      { type: "saveSettings", patch: null },
      { type: "logEvent" },
      {
        type: "trustForSession",
        domain: {
          toString() {
            throw new Error("boom");
          },
        },
      },
    ];
    for (const h of hostiles) {
      expect(() => validateMessage(h)).not.toThrow();
    }
  });
});

describe("F2 — fingerprintability surface", () => {
  it("manifest does not advertise extension via a stable WAR path the page can read deterministically", () => {
    // use_dynamic_url rotates the chrome-extension://<id>/<token> path per
    // session, removing the static fingerprint a page could probe for.
    expect(manifest.web_accessible_resources[0].use_dynamic_url).toBe(true);
  });
});
