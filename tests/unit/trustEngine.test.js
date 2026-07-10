import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const baseSettings = {
  detection: { sensitivity: "balanced" },
  apiKeys: { googleSafeBrowsing: "", virusTotal: "" },
  allowlist: [],
};

describe("evaluateUrl", () => {
  it("scores a clean https domain as safe", async () => {
    const r = await evaluateUrl("https://example.com/", { settings: baseSettings });
    expect(r.status).toBe("safe");
    expect(r.score).toBeGreaterThanOrEqual(90);
    expect(r.summary).toContain("example.com");
  });

  it("penalizes plain http", async () => {
    const r = await evaluateUrl("http://example.com/", { settings: baseSettings });
    expect(r.signals.some((s) => s.id === "no-https")).toBe(true);
    expect(r.score).toBeLessThan(80);
  });

  it("flags lookalike domains as dangerous", async () => {
    const r = await evaluateUrl("https://paypa1.com/login", { settings: baseSettings });
    expect(r.signals.some((s) => s.id === "lookalike")).toBe(true);
    expect(r.status).not.toBe("safe");
  });

  it("flags raw IP hosts", async () => {
    const r = await evaluateUrl("http://192.168.1.1/", { settings: baseSettings });
    expect(r.signals.some((s) => s.id === "ip-host")).toBe(true);
  });

  it("flags embedded credentials in URL", async () => {
    const r = await evaluateUrl("https://user:pass@example.com/", { settings: baseSettings });
    expect(r.signals.some((s) => s.id === "userinfo")).toBe(true);
  });

  it("respects sensitivity multiplier", async () => {
    const lenient = await evaluateUrl("http://example.com/", {
      settings: { ...baseSettings, detection: { sensitivity: "lenient" } },
    });
    const strict = await evaluateUrl("http://example.com/", {
      settings: { ...baseSettings, detection: { sensitivity: "strict" } },
    });
    expect(strict.score).toBeLessThan(lenient.score);
  });

  it("learns trusted domains and raises floor", async () => {
    const r = await evaluateUrl("https://example.com/", {
      settings: baseSettings,
      safeDomainStats: { "example.com": { trustCount: 5, lastTrustAt: Date.now() } },
    });
    expect(r.signals.some((s) => s.id === "learned-safe")).toBe(true);
    expect(r.score).toBeGreaterThanOrEqual(70);
  });

  it("respects allowlist override", async () => {
    const r = await evaluateUrl("http://example.com/", {
      settings: { ...baseSettings, allowlist: ["example.com"] },
    });
    expect(r.score).toBeGreaterThanOrEqual(85);
    expect(r.signals.some((s) => s.id === "allowlist")).toBe(true);
  });

  it("includes contributions and a confidence score", async () => {
    const r = await evaluateUrl("http://paypa1.com/login-verify-secure-account", {
      settings: baseSettings,
    });
    expect(typeof r.confidence).toBe("number");
    const fired = r.signals.filter((s) => s.contribution < 0);
    expect(fired.length).toBeGreaterThan(0);
    fired.forEach((s) => expect(s.contribution).toBeLessThanOrEqual(0));
  });

  it("returns a graceful error for invalid URLs", async () => {
    const r = await evaluateUrl("not a url", { settings: baseSettings });
    expect(r.signals.some((s) => s.id === "error")).toBe(true);
  });
});
