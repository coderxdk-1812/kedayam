import { describe, it, expect, beforeEach } from "vitest";
import { DiagnosticsBuffer, redact, diagnostics } from "../../extension/lib/diagnostics.js";

describe("diagnostics", () => {
  beforeEach(() => diagnostics.disable());

  it("is disabled by default", () => {
    const d = new DiagnosticsBuffer();
    d.record("nav", { url: "https://a.example/x?secret=abc" });
    expect(d.snapshot().length).toBe(0);
  });

  it("when enabled, redacts URLs to host", () => {
    const d = new DiagnosticsBuffer();
    d.enable();
    d.record("nav", { url: "https://a.example/x?secret=abc" });
    const e = d.snapshot()[0];
    expect(e.data.url).toBe("a.example");
  });

  it("redacts emails, tokens, and long strings", () => {
    expect(redact("alice@example.com")).toBe("[email]");
    expect(redact("AKIAIOSFODNN7EXAMPLEXXX")).toBe("[token]");
    const r = redact("x".repeat(100));
    expect(typeof r === "string" && r.endsWith("[trunc]")).toBe(true);
  });

  it("redacts sensitive keys", () => {
    const r = redact({ password: "hunter2", normal: 1 });
    expect(r.password).toBe("[redacted]");
    expect(r.normal).toBe(1);
  });

  it("rejects __proto__ keys", () => {
    const payload = JSON.parse('{"a":1, "__proto__":{"polluted":true}}');
    const r = redact(payload);
    expect(r.polluted).toBeUndefined();
    expect(({}).polluted).toBeUndefined();
  });

  it("buffer is bounded", () => {
    const d = new DiagnosticsBuffer(3);
    d.enable();
    for (let i = 0; i < 10; i++) d.record("k", { i });
    expect(d.snapshot().length).toBe(3);
  });

  it("disable wipes the buffer", () => {
    const d = new DiagnosticsBuffer();
    d.enable();
    d.record("k", {});
    d.disable();
    expect(d.snapshot().length).toBe(0);
  });
});
