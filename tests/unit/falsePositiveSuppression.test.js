// Real-world false-positive suppression for the sensitive data engine.
// These regressions guard against warning fatigue on dev/docs/test content.
import { describe, it, expect } from "vitest";
import { analyzeSensitivePayload, _internal } from "../../extension/lib/sensitiveDataEngine.js";

describe("false positive suppression", () => {
  it("suppresses placeholder Stripe key in tutorial copy", () => {
    const text = "Use your secret key like sk_test_your_key_here in process.env.STRIPE_KEY";
    const v = analyzeSensitivePayload(text);
    const live = v.findings.filter((f) => !f.suppressed);
    expect(live.find((f) => f.id === "stripe_secret")).toBeUndefined();
  });

  it("suppresses classic mock credit card numbers", () => {
    const v = analyzeSensitivePayload("Pay with 4242 4242 4242 4242");
    const live = v.findings.filter((f) => !f.suppressed && f.id === "credit_card");
    expect(live.length).toBe(0);
  });

  it("does not flag generic high-entropy hashes without structure", () => {
    // SHA-256 hex digest — high entropy, but no known structure.
    const text = "commit 9b74c9897bac770ffc029102a200c5de7c0e1f5e6c2d8a9b3f1a7e4d2c5a8b1f";
    const v = analyzeSensitivePayload(text);
    const strong = v.findings.filter((f) => !f.suppressed && f.confidence >= 0.85);
    expect(strong.length).toBe(0);
  });

  it("softens findings in documentation contexts", () => {
    const text = "Example: process.env.AWS_SECRET = AKIAIOSFODNN7EXAMPLE; // see docs";
    const v = analyzeSensitivePayload(text);
    // AWS key pattern still detected, but the EXAMPLE token must suppress it.
    const live = v.findings.filter((f) => !f.suppressed);
    expect(live.find((f) => f.id === "aws_access_key")).toBeUndefined();
  });

  it("placeholder detector catches common dummy phrases", () => {
    expect(_internal.hasPlaceholderToken("your_api_key_here")).toBe(true);
    expect(_internal.hasPlaceholderToken("placeholder for token")).toBe(true);
    expect(_internal.hasPlaceholderToken("ghp_realLookingValue1234")).toBe(false);
  });

  it("mock number detector catches all-same-digit and 4242", () => {
    expect(_internal.looksLikeMockNumber("0000000000000000")).toBe(true);
    expect(_internal.looksLikeMockNumber("4242 4242 4242 4242")).toBe(true);
    expect(_internal.looksLikeMockNumber("4111 1111 1111 1111")).toBe(false);
  });
});
