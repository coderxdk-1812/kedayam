import { describe, it, expect } from "vitest";
import { classifyScareware } from "../../extension/lib/scarewareGuard.js";

describe("classifyScareware", () => {
  it("flags a classic tech-support scam page", () => {
    const r = classifyScareware({
      visibleText:
        "WARNING! Your computer is infected with a virus. Windows Defender detected spyware. " +
        "Call Microsoft support now toll-free. Do not close this window or restart.",
      hasTelLink: true,
    });
    expect(r.scam).toBe(true);
    expect(r.confidence).toBeGreaterThan(0.6);
    expect(r.reasons.length).toBeGreaterThan(1);
  });

  it("flags a fullscreen-lock scam without an explicit tel link", () => {
    const r = classifyScareware({
      visibleText:
        "Your system is locked. Virus detected. Do not shut down. Call now: +1 800 555 0199.",
      fullscreen: true,
    });
    expect(r.scam).toBe(true);
  });

  it("does NOT flag a security blog discussing scams", () => {
    const r = classifyScareware({
      visibleText:
        "In this article we explain how tech-support scams trick users into trusting fake warnings.",
    });
    expect(r.scam).toBe(false);
  });

  it("does NOT fire on alarmist text alone (no call-to-action or lock)", () => {
    const r = classifyScareware({ visibleText: "virus detected on your system" });
    expect(r.scam).toBe(false);
  });

  it("does NOT flag an ordinary antivirus product page", () => {
    const r = classifyScareware({
      visibleText: "Norton 360 protects your devices from malware. Buy now and stay protected.",
    });
    expect(r.scam).toBe(false);
  });

  it("is safe on empty input", () => {
    expect(classifyScareware({}).scam).toBe(false);
  });
});
