// Regression: authFlow anomaly `explain` text must propagate end-to-end —
// from content-script snapshot through message sanitization, behavioral
// rules, the trust engine, and into the explainability payload that the
// popup renders. Historical bug: messageSchemas.safeAuthFlow read `detail`
// while every other layer wrote/read `explain`, blanking popup text for
// authFlow-derived findings without affecting scoring.

import { describe, it, expect } from "vitest";
import { sanitizePageContext } from "../../extension/lib/messageSchemas.js";
import { ruleCredentialRelay } from "../../extension/lib/rules/behavioral/credentialRelay.js";
import { ruleOauthTokenDrift } from "../../extension/lib/rules/behavioral/oauthTokenDrift.js";
import { explainVerdict } from "../../extension/lib/explanation.js";

const EXPLAIN_RELAY =
  "Credential step targets https://evil.example, which is not part of the visited auth flow.";
const EXPLAIN_DRIFT =
  "OAuth token arrives on an origin different from the issuer.";

function snapshotFromContent() {
  // Mirrors the shape produced by buildAuthFlowSnapshot() in content.js.
  return {
    pageOrigin: "https://login.example",
    title: "Sign in",
    visibleText: "Sign in",
    favicon: "",
    hasPasswordField: true,
    topLevelIframe: false,
    scripts: [], styles: [], images: [], links: [], oauthButtons: [],
    forms: [],
    authFlow: {
      state: "credential-step",
      anomalies: [
        { id: "credential-relay", severity: "high", explain: EXPLAIN_RELAY },
        { id: "oauth-token-drift", severity: "high", explain: EXPLAIN_DRIFT },
      ],
    },
  };
}

describe("authFlow explanation propagation", () => {
  it("sanitizePageContext preserves anomaly.explain text", () => {
    const clean = sanitizePageContext(snapshotFromContent());
    expect(clean.authFlow.anomalies[0].explain).toBe(EXPLAIN_RELAY);
    expect(clean.authFlow.anomalies[1].explain).toBe(EXPLAIN_DRIFT);
  });

  it("behavioral rules carry explain text through evaluation", () => {
    const clean = sanitizePageContext(snapshotFromContent());
    const ctx = { authFlow: clean.authFlow };
    const r1 = ruleCredentialRelay.evaluate(ctx);
    const r2 = ruleOauthTokenDrift.evaluate(ctx);
    expect(r1.matched).toBe(true);
    expect(r1.explain).toBe(EXPLAIN_RELAY);
    expect(r2.matched).toBe(true);
    expect(r2.explain).toBe(EXPLAIN_DRIFT);
  });

  it("explainVerdict renders non-empty detail for authFlow signals", () => {
    const clean = sanitizePageContext(snapshotFromContent());
    const anom = clean.authFlow.anomalies[0];
    const verdict = {
      url: "https://login.example/", host: "login.example", root: "example",
      score: 20, status: "dangerous",
      phishingConfidence: 0.8, cloneConfidence: 0,
      signals: [{
        id: "credential-relay",
        title: "Credential relay detected",
        severity: "high", category: "behavior",
        contribution: -50, detail: anom.explain,
      }],
      trustAdds: [],
      arbitration: { rules: [] },
    };
    const x = explainVerdict(verdict);
    expect(x.contributingRisks[0].detail).toBe(EXPLAIN_RELAY);
    expect(x.contributingRisks[0].detail.length).toBeGreaterThan(0);
  });

  it("accepts legacy `detail` alias without blanking text", () => {
    const legacy = snapshotFromContent();
    legacy.authFlow.anomalies = [
      { id: "credential-relay", severity: "high", detail: EXPLAIN_RELAY },
    ];
    const clean = sanitizePageContext(legacy);
    expect(clean.authFlow.anomalies[0].explain).toBe(EXPLAIN_RELAY);
  });

  it("normalizes malformed explain fields safely", () => {
    const bad = snapshotFromContent();
    bad.authFlow.anomalies = [
      { id: "credential-relay", severity: "high", explain: 12345 },
      { id: "oauth-token-drift", severity: "high" /* missing */ },
      { id: "iframe-origin-swap", severity: "high",
        explain: "x".repeat(10_000) },
    ];
    const clean = sanitizePageContext(bad);
    expect(clean.authFlow.anomalies[0].explain).toBe("");
    expect(clean.authFlow.anomalies[1].explain).toBe("");
    expect(clean.authFlow.anomalies[2].explain.length).toBe(256);
  });

  it("scoring is unchanged: contributions remain stable", () => {
    const clean = sanitizePageContext(snapshotFromContent());
    const ctx = { authFlow: clean.authFlow };
    expect(ruleCredentialRelay.evaluate(ctx).contribution).toBe(-50);
    expect(ruleOauthTokenDrift.evaluate(ctx).contribution).toBe(-35);
  });
});
