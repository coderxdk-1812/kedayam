import { describe, it, expect } from "vitest";
import { scanText, shannonEntropy, highestSeverity } from "../../extension/lib/detectors.js";

const REGIONS = { regions: { india: true, us: true, eu: true, global: true } };

describe("scanText", () => {
  it("detects a valid credit card via Luhn", () => {
    const f = scanText("card 4242 4242 4242 4242", REGIONS);
    expect(f.find((x) => x.kind === "creditCard")).toBeTruthy();
  });
  it("rejects a non-Luhn 16-digit number", () => {
    const f = scanText("1234 5678 9012 3456", REGIONS);
    expect(f.find((x) => x.kind === "creditCard")).toBeFalsy();
  });
  it("detects Aadhaar when India region enabled", () => {
    const f = scanText("aadhaar 1234 5678 9012", REGIONS);
    expect(f.find((x) => x.kind === "aadhaar")).toBeTruthy();
  });
  it("does not detect Aadhaar when India region disabled", () => {
    const f = scanText("1234 5678 9012", { regions: { india: false, us: true, eu: true, global: true } });
    expect(f.find((x) => x.kind === "aadhaar")).toBeFalsy();
  });
  it("detects PAN", () => {
    expect(scanText("PAN ABCDE1234F", REGIONS).find((x) => x.kind === "pan")).toBeTruthy();
  });
  it("detects SSN", () => {
    expect(scanText("ssn 123-45-6789", REGIONS).find((x) => x.kind === "ssn")).toBeTruthy();
  });
  it("detects AWS access key", () => {
    expect(scanText("AKIAIOSFODNN7EXAMPLE", REGIONS).find((x) => x.kind === "awsKey")).toBeTruthy();
  });
  it("detects GitHub PAT", () => {
    expect(scanText("token ghp_abcdefghijklmnopqrstuvwxyz0123456789", REGIONS).find((x) => x.kind === "ghToken")).toBeTruthy();
  });
  it("redacts the captured value", () => {
    const f = scanText("test@example.com", REGIONS);
    const email = f.find((x) => x.kind === "email");
    expect(email.value).not.toBe("test@example.com");
    expect(email.value).toMatch(/•/);
  });
  it("returns empty on empty input", () => {
    expect(scanText("", REGIONS)).toEqual([]);
  });
});

describe("shannonEntropy", () => {
  it("is 0 for a uniform string", () => expect(shannonEntropy("aaaaa")).toBe(0));
  it("is high for random tokens", () => {
    expect(shannonEntropy("aB3xZ9qLm2pQ7rT4")).toBeGreaterThan(3.5);
  });
});

describe("highestSeverity", () => {
  it("picks critical over high", () => {
    expect(highestSeverity([{ severity: "high" }, { severity: "critical" }])).toBe("critical");
  });
});
