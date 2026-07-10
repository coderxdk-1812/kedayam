import { describe, it, expect } from "vitest";
import { buildArbitrationTrace } from "../../extension/lib/arbitrationTrace.js";

describe("arbitrationTrace", () => {
  it("groups escalations, caps and informational rules", () => {
    const t = buildArbitrationTrace({
      score: 18,
      baselineScore: 65,
      arbitration: {
        forceStatus: "dangerous",
        cap: 20,
        trustFloor: null,
        rules: [
          { id: "external-post", force: "dangerous", cap: 20, reason: "off-domain post" },
          { id: "clone-soft", cap: 55, reason: "soft clone" },
          { id: "auth-keyword", reason: "hostname keyword" },
        ],
      },
      decay: {
        delta: 30,
        anomalies: [{ id: "external-credential-post", points: 60, explain: "off-dom" }],
      },
      suspicion: {
        level: "dangerous",
        modal: "hard",
        blockingUx: true,
        popupBanner: true,
        badgeTint: "red",
      },
      trustedRoot: true,
      behavioralEvidence: true,
    });
    expect(t.escalations.length).toBe(1);
    expect(t.caps.length).toBe(1);
    expect(t.informational.length).toBe(1);
    expect(t.decay.delta).toBe(30);
    expect(t.explain.some((l) => /Forced dangerous/.test(l))).toBe(true);
    expect(Object.isFrozen(t)).toBe(true);
  });

  it("never throws on empty input", () => {
    expect(() => buildArbitrationTrace({})).not.toThrow();
    const t = buildArbitrationTrace({});
    expect(t.rules).toEqual([]);
  });
});
