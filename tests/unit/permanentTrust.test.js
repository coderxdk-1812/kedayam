// Permanent trust ("Always trust this site") + VirusTotal second-opinion link.
//
// Covers the three moving parts of the feature:
//   1. the `trustPermanent` message schema (validation + provenance class),
//   2. the trust engine's treatment of an allowlisted root (no longer flagged),
//   3. the VirusTotal URL shape used by the warning modal and the popup.
import { describe, it, expect } from "vitest";
import { validateMessage, TRUST_MUTATION_TYPES } from "../../extension/lib/messageSchemas.js";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";
import { DEFAULT_SETTINGS } from "../../extension/lib/storage.js";

// Mirror of the helper inlined in content.js / popup.js. Only the ORIGIN is
// handed to VirusTotal — never the path or query string, which can carry
// session tokens or personal data.
function virusTotalUrl(href) {
  const u = new URL(href);
  return `https://www.virustotal.com/gui/search?query=${encodeURIComponent(`${u.origin}/`)}`;
}

describe("trustPermanent message schema", () => {
  it("accepts a plain hostname", () => {
    const r = validateMessage({ type: "trustPermanent", domain: "now.hdfc.bank.in" });
    expect(r).toMatchObject({ ok: true, type: "trustPermanent" });
    expect(r.value).toEqual({ domain: "now.hdfc.bank.in" });
  });

  it("rejects a missing, empty, or malformed domain", () => {
    for (const domain of [undefined, "", "not a domain", "<script>", "a".repeat(300)]) {
      expect(validateMessage({ type: "trustPermanent", domain }).ok).toBe(false);
    }
  });

  it("is classified as a trust mutation (requires a tab or extension-page sender)", () => {
    expect(TRUST_MUTATION_TYPES.has("trustPermanent")).toBe(true);
  });

  it("strips unknown fields — a page can never smuggle an arbitrary root through", () => {
    const r = validateMessage({
      type: "trustPermanent",
      domain: "example.com",
      allowlist: ["bank.com"],
    });
    expect(r.ok).toBe(true);
    expect(Object.keys(r.value)).toEqual(["domain"]);
  });
});

describe("allowlisted root is no longer flagged", () => {
  const url = "https://secure-login.paypa1-verify.tk/signin";
  const pageContext = {
    pageOrigin: "https://secure-login.paypa1-verify.tk",
    title: "Sign in to PayPal",
    visibleText: "Sign in to PayPal Password Email",
    hasPasswordField: true,
    forms: [{ hasPassword: true, hasEmailLike: true, fieldCount: 3, hiddenFields: 0 }],
  };

  it("flags the page without an allowlist entry", async () => {
    const r = await evaluateUrl(url, { settings: DEFAULT_SETTINGS, pageContext });
    expect(r.status).not.toBe("safe");
  });

  it("stops flagging once the root is permanently trusted", async () => {
    const settings = { ...DEFAULT_SETTINGS, allowlist: ["paypa1-verify.tk"] };
    const r = await evaluateUrl(url, { settings, pageContext });
    expect(r.score).toBeGreaterThan(60);
    expect(r.status).toBe("safe");
    expect(r.signals.some((s) => s.id === "allowlist" || s.id === "allowlist-trust")).toBe(true);
  });
});

describe("VirusTotal verification link", () => {
  it("uses the documented search-query form", () => {
    expect(virusTotalUrl("https://www.google.com/")).toBe(
      "https://www.virustotal.com/gui/search?query=https%3A%2F%2Fwww.google.com%2F",
    );
  });

  it("never leaks the path or query string of the flagged page", () => {
    const link = virusTotalUrl("https://now.hdfc.bank.in/login?sessionId=SECRET&otp=123456");
    expect(link).toBe(
      "https://www.virustotal.com/gui/search?query=https%3A%2F%2Fnow.hdfc.bank.in%2F",
    );
    expect(link).not.toContain("SECRET");
    expect(link).not.toContain("123456");
  });
});
