// Trust anomaly decay — verifies a trusted root LOSES trust when behavioral
// evidence appears, defeating "trusted-domain blindness".
import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const settings = { detection: { sensitivity: "balanced" }, apiKeys: {}, allowlist: [] };

describe("trust anomaly decay (M3)", () => {
  it("reputable root with NO behavior keeps high trust floor", async () => {
    const r = await evaluateUrl("https://github.com/login", {
      settings,
      pageContext: {
        pageOrigin: "https://github.com",
        title: "Sign in",
        visibleText: "sign in to github",
        hasPasswordField: true,
        forms: [
          {
            action: "https://github.com/session",
            method: "post",
            hasPassword: true,
            hasEmailLike: true,
            hasOtp: false,
            hiddenCount: 0,
            fieldsCount: 2,
            insideIframe: false,
          },
        ],
      },
    });
    expect(r.status).toBe("safe");
    expect(r.score).toBeGreaterThanOrEqual(80);
    expect(r.trustDecay.delta).toBe(0);
  });

  it("compromised reputable root POSTing off-domain loses trust sharply", async () => {
    const r = await evaluateUrl("https://github.com/login", {
      settings,
      pageContext: {
        pageOrigin: "https://github.com",
        title: "Sign in",
        visibleText: "sign in to github",
        hasPasswordField: true,
        forms: [
          {
            action: "https://attacker.cc/grab",
            method: "post",
            hasPassword: true,
            hasEmailLike: true,
            hasOtp: false,
            hiddenCount: 0,
            fieldsCount: 2,
            insideIframe: false,
          },
        ],
      },
    });
    expect(r.trustDecay.delta).toBeGreaterThan(0);
    expect(r.status).toBe("dangerous");
  });

  it("trusted provider with OAuth token drift gets decay anomaly", async () => {
    const r = await evaluateUrl("https://google.com/", {
      settings,
      pageContext: { pageOrigin: "https://google.com", title: "Google" },
      authFlow: {
        anomalies: [{ id: "oauth-token-drift", severity: "high", explain: "Token from elsewhere" }],
      },
    });
    expect(r.trustDecay.anomalies.some((a) => a.id === "oauth-relay-mismatch")).toBe(true);
  });
});
