import { describe, it, expect } from "vitest";
import { trustDecay } from "../../extension/lib/trustDecay.js";

describe("trustDecay", () => {
  it("returns zero delta when not on a trusted root", () => {
    const r = trustDecay({ trustedRoot: false, phishing: { externalFormPost: true } });
    expect(r.delta).toBe(0);
    expect(r.anomalies.length).toBe(0);
  });

  it("decays sharply when a trusted root posts credentials off-domain", () => {
    const r = trustDecay({ trustedRoot: true, phishing: { externalFormPost: true } });
    expect(r.delta).toBeGreaterThanOrEqual(60);
    expect(r.floorOverride).toBeLessThan(60);
    expect(r.anomalies.some((a) => a.id === "external-credential-post")).toBe(true);
  });

  it("decays for iframe credential entry", () => {
    const r = trustDecay({
      trustedRoot: true,
      phishing: { signals: [{ id: "iframe-credential-form" }] },
    });
    expect(r.delta).toBeGreaterThan(0);
    expect(r.anomalies.some((a) => a.id === "cross-origin-cred-iframe")).toBe(true);
  });

  it("decays for OAuth token drift from authFlow", () => {
    const r = trustDecay({
      trustedRoot: true,
      authFlow: { anomalies: [{ id: "oauth-token-drift" }] },
    });
    expect(r.delta).toBeGreaterThan(0);
    expect(r.anomalies.some((a) => a.id === "oauth-relay-mismatch")).toBe(true);
  });

  it("decays mildly for hidden overlay / CSP / redirect storm / mfa split", () => {
    const r = trustDecay({
      trustedRoot: true,
      hiddenLoginOverlay: true,
      cspWeakened: true,
      authFlow: { anomalies: [{ id: "redirect-storm" }, { id: "mfa-origin-split" }] },
    });
    expect(r.delta).toBeGreaterThan(20);
    expect(r.anomalies.length).toBeGreaterThanOrEqual(4);
  });
});
