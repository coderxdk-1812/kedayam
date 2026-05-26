// Adversarial fuzz tests — bounded inputs through every public entry
// point. The test asserts no throws, bounded time, and stable verdicts.

import { describe, it, expect } from "vitest";
import { analyzeSensitivePayload } from "../../extension/lib/sensitiveDataEngine.js";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";
import { safeExecRegex, safeMatchAll, safeJSONParse, assertEnvelope } from "../../extension/lib/selfProtection.js";

function seeded(seed) {
  let s = seed >>> 0 || 1;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 0xffffffff; };
}

function randomString(rand, maxLen) {
  const n = Math.floor(rand() * maxLen);
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@/:;<>?\"' \t\n\u00a0\ud83d\ude00";
  let out = "";
  for (let i = 0; i < n; i++) out += chars[Math.floor(rand() * chars.length)];
  return out;
}

describe("fuzz: sensitiveDataEngine", () => {
  const rand = seeded(42);
  it("never throws and stays bounded over 500 random payloads", () => {
    const start = Date.now();
    for (let i = 0; i < 500; i++) {
      const s = randomString(rand, 1000);
      const v = analyzeSensitivePayload(s);
      expect(v && typeof v.riskLevel === "string").toBe(true);
      // Output never contains raw input characters as a secret value
      for (const f of v.findings) {
        expect(f.redacted).toMatch(/•|\[|trunc|\.\.\./);
      }
    }
    expect(Date.now() - start).toBeLessThan(3000);
  });
  it("handles giant payloads gracefully", () => {
    const big = "x".repeat(500_000);
    const v = analyzeSensitivePayload(big);
    expect(v.riskLevel).toBe("none");
  });
});

describe("fuzz: trustEngine.evaluateUrl", () => {
  const rand = seeded(7);
  it("returns a verdict object for malformed URLs and unicode garbage", async () => {
    const settings = { detection: { sensitivity: "balanced" }, apiKeys: {}, allowlist: [] };
    for (let i = 0; i < 80; i++) {
      const u = randomString(rand, 200);
      const r = await evaluateUrl(u, { settings });
      expect(r && typeof r.status === "string").toBe(true);
    }
  });
});

describe("fuzz: selfProtection primitives", () => {
  it("safeExecRegex / safeMatchAll never hang on adversarial inputs", () => {
    // Classic catastrophic-backtracking patterns
    const re = /^(a+)+$/;
    const start = Date.now();
    expect(safeExecRegex(re, "a".repeat(30) + "!")).not.toBeUndefined();
    safeMatchAll(/(a+)+/, "a".repeat(100) + "!", { deadlineMs: 50 });
    expect(Date.now() - start).toBeLessThan(500);
  });
  it("safeJSONParse rejects oversize without throwing", () => {
    expect(safeJSONParse("x".repeat(2_000_000))).toBeNull();
  });
  it("assertEnvelope tolerates random objects", () => {
    expect(assertEnvelope({})).toBe(false);
    expect(assertEnvelope({ type: 1 })).toBe(false);
    expect(assertEnvelope({ type: "x".repeat(80) })).toBe(false);
  });
});

describe("fuzz: phishing context fuzz", () => {
  it("never throws on adversarial form arrays", () => {
    for (let i = 0; i < 50; i++) {
      const forms = Array.from({ length: i }, (_, k) => ({
        action: k % 2 === 0 ? "javascript:void(0)" : "https://x.example/" + k,
        method: "post",
        hasPassword: k % 3 === 0,
        hasEmailLike: k % 2 === 1,
        hasOtp: k % 5 === 0,
        hiddenCount: k,
        fieldsCount: k + 1,
        insideIframe: k % 7 === 0,
      }));
      const r = analyzePhishing({
        pageOrigin: "https://fuzz.example/" + i,
        title: "T".repeat(i),
        visibleText: "fuzz ".repeat(i),
        forms,
        hasPasswordField: forms.some((f) => f.hasPassword),
      });
      expect(r && typeof r.confidence === "number").toBe(true);
    }
  });
});
