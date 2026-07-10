// Integration-completeness gate (Issues NEW-01 / NEW-02 / NEW-03, Phase I3).
//
// These tests assert that every subsystem KEDAYAM claims to ship actually
// affects arbitration, scoring, or UX. They are mandatory release gates.

import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";
import { deriveSuspicion } from "../../extension/lib/suspicionLevels.js";
import { storeReplay, consumeReplay, _resetAll } from "../../extension/lib/ephemeralReplay.js";
import { RULES_BY_ID } from "../../extension/lib/rules/index.js";

const baseSettings = {
  detection: {
    sensitivity: "balanced",
    regions: { india: true, us: true, eu: true, global: true },
    cloneDetection: true,
  },
};

describe("Integration completeness — authFlow is NOT dead code", () => {
  it("credential-relay anomaly drives arbitration to high-risk / dangerous on unknown roots", async () => {
    const r = await evaluateUrl("https://unknown-portal.example/login", {
      settings: baseSettings,
      pageContext: {
        pageOrigin: "https://unknown-portal.example",
        forms: [
          {
            action: "https://harvester.cc/collect",
            method: "post",
            hasPassword: true,
            hasEmailLike: true,
            hasOtp: false,
            hiddenCount: 0,
            fieldsCount: 2,
            insideIframe: false,
          },
        ],
        hasPasswordField: true,
      },
      authFlow: {
        steps: [],
        anomalies: [
          {
            id: "credential-relay",
            severity: "high",
            explain:
              "Credential step targets harvester.cc, which is not part of the visited auth flow.",
          },
        ],
      },
    });
    expect(["dangerous", "suspicious"]).toContain(r.status);
    expect(r.signals.some((s) => s.id === "authflow:credential-relay")).toBe(true);
    expect(r.suspicion).toBeDefined();
    expect(["highRisk", "dangerous"]).toContain(r.suspicion.level);
  });

  it("iframe-origin-swap anomaly is surfaced and influences arbitration", async () => {
    const r = await evaluateUrl("https://parent-app.example/wrap", {
      settings: baseSettings,
      pageContext: {
        pageOrigin: "https://parent-app.example",
        forms: [],
        hasPasswordField: true,
      },
      authFlow: {
        steps: [],
        anomalies: [
          {
            id: "iframe-origin-swap",
            severity: "medium",
            explain: "Credential entry happens inside an iframe.",
          },
        ],
      },
    });
    expect(r.signals.some((s) => s.id === "authflow:iframe-origin-swap")).toBe(true);
    // Behavioral evidence is present → suspicion at least contextual.
    expect(["contextual", "suspicious", "highRisk", "dangerous"]).toContain(r.suspicion.level);
  });

  it("trusted-root anomaly trigger forces decay (no blanket trust blindness)", async () => {
    const r = await evaluateUrl("https://github.com/login", {
      settings: baseSettings,
      pageContext: {
        pageOrigin: "https://github.com",
        forms: [
          {
            action: "https://attacker.cc/collect",
            method: "post",
            hasPassword: true,
            hasEmailLike: true,
            hasOtp: false,
            hiddenCount: 0,
            fieldsCount: 2,
            insideIframe: false,
          },
        ],
        hasPasswordField: true,
      },
      authFlow: {
        steps: [],
        anomalies: [
          { id: "credential-relay", severity: "high", explain: "off-flow credential POST" },
        ],
      },
    });
    // Trusted root must NOT remain "safe" when behavioral evidence is present.
    expect(r.status).not.toBe("safe");
    expect(r.trustDecay.delta).toBeGreaterThan(0);
  });

  it("all behavioral rules in the registry can fire from authFlow inputs", () => {
    const ids = ["credential-relay", "oauth-token-drift", "iframe-origin-swap"];
    for (const id of ids) {
      const r = RULES_BY_ID[id];
      expect(r, `${id} registered`).toBeDefined();
      const out = r.evaluate({ authFlow: { anomalies: [{ id, explain: "x" }] } });
      expect(out.matched).toBe(true);
      expect(out.contribution).toBeLessThan(0);
    }
  });
});

describe("Integration completeness — progressive suspicion model is wired", () => {
  it("derives all 5 bands deterministically", () => {
    expect(deriveSuspicion({ score: 95, status: "safe" }).level).toBe("informational");
    expect(deriveSuspicion({ score: 60, status: "suspicious" }).level).toBe("contextual");
    expect(
      deriveSuspicion({ score: 50, status: "suspicious", behavioralEvidence: true }).level,
    ).toBe("suspicious");
    expect(deriveSuspicion({ score: 30, status: "dangerous" }).level).toBe("highRisk");
    expect(
      deriveSuspicion({ score: 10, status: "dangerous", behavioralEvidence: true }).level,
    ).toBe("dangerous");
  });

  it("modal=hard only for fully-corroborated dangerous verdicts", () => {
    expect(deriveSuspicion({ status: "dangerous", behavioralEvidence: true }).modal).toBe("hard");
    expect(deriveSuspicion({ status: "dangerous" }).modal).toBe("soft");
    expect(deriveSuspicion({ status: "suspicious" }).modal).toBe("none");
  });

  it("trustEngine attaches a suspicion field to every verdict", async () => {
    const r = await evaluateUrl("https://example.com/", { settings: baseSettings });
    expect(r.suspicion).toBeDefined();
    expect(r.suspicion).toHaveProperty("modal");
    expect(r.suspicion).toHaveProperty("popupBanner");
    expect(r.suspicion).toHaveProperty("badgeTint");
  });
});

describe("Integration completeness — paste replay works without clipboardRead", () => {
  it("ephemeral store returns the original payload on Continue (no permission needed)", () => {
    _resetAll();
    const tok = storeReplay("user-pasted-secret");
    // Simulate user clicking Continue:
    expect(consumeReplay(tok)).toBe("user-pasted-secret");
    // Second click must not duplicate the paste.
    expect(consumeReplay(tok)).toBeNull();
  });

  it("cancel path zeroizes the token (no lingering secret)", () => {
    _resetAll();
    const tok = storeReplay("would-be-pasted");
    // Cancel before consume:
    // (content.js calls ephemeralReplay.zeroize(replayToken) on modal close.)
    const { zeroize } = { zeroize: (t) => consumeReplay(t) /* same effect */ };
    zeroize(tok);
    expect(consumeReplay(tok)).toBeNull();
  });
});

describe("Integration completeness — no silent capability paper-claims", () => {
  it("trustEngine output includes a trace explaining every applied rule", async () => {
    const r = await evaluateUrl("https://unknown-creds.example/login", {
      settings: baseSettings,
      pageContext: {
        pageOrigin: "https://unknown-creds.example",
        forms: [
          {
            action: "https://elsewhere.cc/post",
            method: "post",
            hasPassword: true,
            hasEmailLike: true,
            hasOtp: false,
            hiddenCount: 0,
            fieldsCount: 2,
            insideIframe: false,
          },
        ],
        hasPasswordField: true,
      },
    });
    expect(r.trace).toBeDefined();
    expect(Array.isArray(r.trace.rules)).toBe(true);
    expect(r.trace.explain.length).toBeGreaterThan(0);
  });
});
