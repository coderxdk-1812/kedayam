// Regression: v7 audit finding — phishing.credentialHarvest (same-origin
// password POST) must be treated as behavioral evidence and bypass
// contextual dampening, even on pages that look educational.
import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const settings = {
  detection: { sensitivity: "balanced" },
  apiKeys: { googleSafeBrowsing: "", virusTotal: "" },
  allowlist: [],
};

describe("credentialHarvest bypasses dampening", () => {
  it("educational-flavored host with same-origin credential POST is not damped", async () => {
    // Compound dampening context (doc prefix + auth-doc vocab + edu terms)
    // PLUS a real password form posting same-origin. Without the fix this
    // would damp visual signals; with the fix credentialHarvest gates it off.
    const r = await evaluateUrl("https://learn.acme-training.tld/tutorial/oauth-login", {
      settings,
      pageContext: {
        pageOrigin: "https://learn.acme-training.tld",
        title: "OAuth 2.0 tutorial — sign in to your Microsoft account",
        visibleText:
          "tutorial demo example getting started OAuth 2.0 authorization " +
          "code flow PKCE redirect_uri client_id access token " +
          "outlook office 365 sign in to your account",
        forms: [{
          action: "/login", method: "post",
          hasPassword: true, hasEmailLike: true, hasOtp: false,
          hiddenCount: 0, fieldsCount: 2, insideIframe: false,
        }],
        hasPasswordField: true,
      },
    });
    // No security-context dampening should have been applied.
    const sc = r.signals.find((s) => s.id === "security-context");
    expect(sc).toBeUndefined();
    expect(r.status).not.toBe("safe");
  });

  it("research-flavored docs page WITHOUT a password form still gets dampened", async () => {
    // Sanity: the bypass must not over-trigger on pages that merely discuss auth.
    const r = await evaluateUrl("https://docs.stripe.com/connect/oauth-reference", {
      settings,
      pageContext: {
        pageOrigin: "https://docs.stripe.com",
        title: "OAuth 2.0 reference",
        visibleText:
          "documentation reference tutorial example OAuth 2.0 authorization " +
          "code flow PKCE redirect_uri client_id access token",
        forms: [],
        hasPasswordField: false,
      },
    });
    expect(r.status).not.toBe("dangerous");
  });
});
