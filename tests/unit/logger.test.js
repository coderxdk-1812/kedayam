import { describe, it, expect } from "vitest";
import { Logger, redact } from "../../extension/lib/logger.js";

describe("Logger", () => {
  it("respects min level", () => {
    const l = new Logger({ level: "warn" });
    l.debug("d");
    l.info("i");
    l.warn("w");
    l.error("e");
    const recent = l.recent();
    expect(recent.map((r) => r.level)).toEqual(["warn", "error"]);
  });
  it("ring-buffers to a max size", () => {
    const l = new Logger({ level: "debug" });
    for (let i = 0; i < 250; i++) l.info("m" + i);
    expect(l.recent(1000).length).toBeLessThanOrEqual(200);
  });
});

describe("redact", () => {
  it("masks AWS keys and GitHub tokens in strings", () => {
    const out = redact("AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out).not.toContain("ghp_");
  });
  it("masks values under sensitive keys in objects", () => {
    const out = redact({ token: "abc", nested: { password: "p", safe: "ok" } });
    expect(out.token).toBe("«redacted»");
    expect(out.nested.password).toBe("«redacted»");
    expect(out.nested.safe).toBe("ok");
  });
});
