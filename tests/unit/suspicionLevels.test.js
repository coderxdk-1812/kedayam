import { describe, it, expect } from "vitest";
import { deriveSuspicion, suspicionAtLeast } from "../../extension/lib/suspicionLevels.js";

describe("progressive suspicion model", () => {
  it("safe high score stays informational", () => {
    const s = deriveSuspicion({ score: 95, status: "safe" });
    expect(s.level).toBe("informational");
    expect(s.modal).toBe("none");
    expect(s.badgeTint).toBe("green");
  });

  it("dangerous WITHOUT behavioral evidence stays at highRisk (soft modal)", () => {
    const s = deriveSuspicion({ score: 20, status: "dangerous" });
    expect(s.level).toBe("highRisk");
    expect(s.modal).toBe("soft");
  });

  it("dangerous WITH behavioral evidence escalates to hard modal", () => {
    const s = deriveSuspicion({ score: 15, status: "dangerous", behavioralEvidence: true });
    expect(s.level).toBe("dangerous");
    expect(s.modal).toBe("hard");
    expect(s.blockingUx).toBe(true);
  });

  it("suspicious without behavioral evidence is contextual (no toast modal)", () => {
    const s = deriveSuspicion({ score: 55, status: "suspicious" });
    expect(s.level).toBe("contextual");
    expect(s.modal).toBe("none");
  });

  it("trusted root with mild anomaly delta moves to contextual", () => {
    const s = deriveSuspicion({ score: 90, status: "safe", trustedRoot: true, anomalyDelta: 10 });
    expect(s.level).toBe("contextual");
  });

  it("trusted root without behavioral evidence cannot go to hard modal", () => {
    const s = deriveSuspicion({
      score: 30,
      status: "dangerous",
      trustedRoot: true,
      behavioralEvidence: false,
    });
    // would normally be highRisk; trustedRoot downgrades it.
    expect(["suspicious", "contextual", "highRisk"].includes(s.level)).toBe(true);
    expect(s.modal).not.toBe("hard");
  });

  it("ordering helper works", () => {
    expect(suspicionAtLeast("dangerous", "suspicious")).toBe(true);
    expect(suspicionAtLeast("informational", "contextual")).toBe(false);
  });
});
