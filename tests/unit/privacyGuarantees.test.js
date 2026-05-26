// Privacy invariants. If any of these break, raw secrets could leave the
// detection pipeline. These tests must stay green forever.
import { describe, it, expect } from "vitest";
import { analyzeSensitivePayload } from "../../extension/lib/sensitiveDataEngine.js";

const SECRETS = [
  "AKIAABCDEFGHIJKLMNOP",
  "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sk_live_abcdefghijklmnopqrstuvwxyz",
  "-----BEGIN RSA PRIVATE KEY-----",
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepartherevalid",
];

describe("privacy guarantees", () => {
  it("never returns the raw secret in any finding", () => {
    const text = SECRETS.join("\n");
    const v = analyzeSensitivePayload(text);
    expect(v.findings.length).toBeGreaterThan(0);
    for (const f of v.findings) {
      // Each finding must expose only a redacted preview, never raw.
      expect("redacted" in f).toBe(true);
      for (const secret of SECRETS) {
        expect(f.redacted).not.toBe(secret);
        expect(f.redacted.includes("•") || f.redacted.length < secret.length).toBe(true);
      }
    }
  });

  it("verdict object contains no field that holds raw text", () => {
    const v = analyzeSensitivePayload("token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const json = JSON.stringify(v);
    expect(json).not.toContain("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  });

  it("refuses to process oversized payloads", () => {
    const huge = "x".repeat(300_000);
    const v = analyzeSensitivePayload(huge);
    expect(v.findings.length).toBe(0);
    expect(v.riskLevel).toBe("none");
  });

  it("returns an empty verdict for non-string input", () => {
    // @ts-expect-error intentionally wrong type
    const v = analyzeSensitivePayload(null);
    expect(v.findings).toEqual([]);
    expect(v.riskScore).toBe(0);
  });
});
