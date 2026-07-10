import { describe, it, expect } from "vitest";
import {
  analyzeSensitivePayload,
  shannonEntropy,
  luhn,
  ibanChecksum,
  verhoeffAadhaar,
  looksLikeMnemonic,
  _internal,
} from "../../extension/lib/sensitiveDataEngine.js";

describe("sensitiveDataEngine — checksums", () => {
  it("luhn validates known good/bad PANs", () => {
    expect(luhn("4111111111111111")).toBe(true); // visa test
    expect(luhn("4111111111111112")).toBe(false);
    expect(luhn("abc")).toBe(false);
  });
  it("ibanChecksum validates a known IBAN", () => {
    expect(ibanChecksum("GB82WEST12345698765432")).toBe(true);
    expect(ibanChecksum("GB82WEST12345698765431")).toBe(false);
  });
  it("verhoeffAadhaar rejects non-12-digit and bad checksums", () => {
    expect(verhoeffAadhaar("12341234123")).toBe(false);
    expect(verhoeffAadhaar("111111111112")).toBe(false);
  });
  it("shannonEntropy is monotonic on randomness", () => {
    expect(shannonEntropy("aaaaaaaa")).toBeLessThan(shannonEntropy("aZ9bX2qK"));
  });
  it("looksLikeMnemonic accepts plausible 12-word phrases", () => {
    const ok =
      "abandon ability able about above absent absorb abstract absurd abuse access accident";
    expect(looksLikeMnemonic(ok)).toBe(true);
    expect(looksLikeMnemonic("aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa")).toBe(
      false,
    );
  });
});

describe("sensitiveDataEngine — detection & suppression", () => {
  it("detects an AWS access key with high confidence", () => {
    const v = analyzeSensitivePayload("token=AKIAIOSFODNN7ABCDEFG in prod");
    expect(v.detectedTypes).toContain("aws_access_key");
    expect(v.riskLevel === "high" || v.riskLevel === "critical").toBe(true);
  });
  it("detects a GitHub classic PAT", () => {
    const v = analyzeSensitivePayload("export GH=ghp_" + "a".repeat(36));
    expect(v.detectedTypes).toContain("github_classic");
  });
  it("detects a Stripe live secret key", () => {
    const v = analyzeSensitivePayload("STRIPE=sk_live_4eC39HqLyjWDarjtT1zdp7dc");
    expect(v.detectedTypes).toContain("stripe_secret");
  });
  it("suppresses placeholder credit card 4242 4242 4242 4242", () => {
    const v = analyzeSensitivePayload("Use test card 4242 4242 4242 4242");
    const live = v.findings.filter((f) => !f.suppressed && f.id === "credit_card");
    expect(live.length).toBe(0);
  });
  it("suppresses placeholder API key with <your_> token", () => {
    const v = analyzeSensitivePayload("API_KEY=<your_api_key_here_xxxxxxxxxxxxxxxxxxxx>");
    expect(v.findings.every((f) => f.suppressed || f.severity !== "critical")).toBe(true);
  });
  it("does not flag a random UUID as a secret", () => {
    const v = analyzeSensitivePayload("id=550e8400-e29b-41d4-a716-446655440000");
    const live = v.findings.filter((f) => !f.suppressed);
    expect(live.length).toBe(0);
  });
  it("Aadhaar must pass Verhoeff to be reported live", () => {
    const v = analyzeSensitivePayload("aadhaar: 1234 5678 9012");
    const live = v.findings.filter((f) => !f.suppressed && f.id === "aadhaar");
    expect(live.length).toBe(0);
  });
  it("redacts every reported value", () => {
    const v = analyzeSensitivePayload("k=AKIAIOSFODNN7ABCDEFG");
    for (const f of v.findings) {
      expect(f.redacted).not.toContain("IOSFODNN7");
      expect(f.redacted).toMatch(/•/);
    }
  });
  it("never returns raw text", () => {
    const v = analyzeSensitivePayload("password=hunter2hunter2hunter2");
    expect(JSON.stringify(v)).not.toContain("hunter2hunter2hunter2");
  });
  it("returns risk level 'none' for benign text", () => {
    const v = analyzeSensitivePayload("Hello world, how are you?");
    expect(v.riskLevel).toBe("none");
    expect(v.riskScore).toBe(0);
  });
  it("placeholder-detector recognizes 'process.env.X'", () => {
    expect(_internal.hasPlaceholderToken("process.env.foo")).toBe(true);
  });
  it("ignores oversized payloads", () => {
    const v = analyzeSensitivePayload("x".repeat(300_000));
    expect(v.riskLevel).toBe("none");
  });
});
