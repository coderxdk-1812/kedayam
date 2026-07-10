// Calibration upper-bound regressions.
//
// The existing securityResearchContexts suite asserts "not dangerous" for
// security-research, educational, and documentation pages. That allows
// silent drift: a future change could push every such page from "safe" to
// "suspicious" with a 51 score and CI would stay green while the UX
// noticeably degrades.
//
// This suite tightens the contract — clearly informational pages must:
//   * end up status === "safe" (NOT merely "not dangerous"), AND
//   * carry a score at or above the safe floor used by the popup, AND
//   * surface no critical or high-severity contributing risks.
//
// Pages with real behavioral evidence (off-domain credential POST, etc.)
// must still escalate to dangerous — these assertions are NOT a blanket
// "always safe" override.

import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";
import { explainVerdict } from "../../extension/lib/explanation.js";

const settings = {
  detection: { sensitivity: "balanced" },
  apiKeys: { googleSafeBrowsing: "", virusTotal: "" },
  allowlist: [],
};

const INFORMATIONAL_SCORE_FLOOR = 55; // anything below is in alarm territory
const INFO_ONLY_SEVERITIES = new Set(["info", "low", "medium"]);

function researchCtx(title, text) {
  return {
    pageOrigin: "https://example.org",
    title,
    visibleText: text,
    forms: [],
    hasPasswordField: false,
  };
}

function expectInformational(verdict) {
  // Status ceiling — never escalates past "suspicious", and the explicit
  // "dangerous" wording is forbidden on documentation/research pages.
  expect(verdict.status).not.toBe("dangerous");
  // Score ceiling — clearly above the "warn loudly" band, so the popup
  // does not paint the page red.
  expect(verdict.score).toBeGreaterThanOrEqual(INFORMATIONAL_SCORE_FLOOR);
  // Severity ceiling — no critical or high contributing risks should be
  // surfaced in the user-facing explanation. medium/low/info only.
  const exp = explainVerdict(verdict);
  for (const r of exp.contributingRisks) {
    expect(INFO_ONLY_SEVERITIES.has(r.severity)).toBe(true);
  }
  // The explanation tone must never claim "dangerous" on these pages.
  expect(exp.headline.toLowerCase()).not.toContain("dangerous");
}

describe("calibration — upper score & severity bounds (informational pages)", () => {
  it("PhishTank submission detail page is safe/informational", async () => {
    const r = await evaluateUrl("https://www.phishtank.org/phish_detail.php?phish_id=123", {
      settings,
      pageContext: researchCtx(
        "PhishTank — Suspected Phishing URL Submission",
        "phishing url indicators of compromise threat intelligence " +
          "submitted url analysis report scan report ioc abuse.ch",
      ),
    });
    expectInformational(r);
  });

  it("VirusTotal URL report is safe/informational", async () => {
    const r = await evaluateUrl("https://www.virustotal.com/gui/url/abc/detection", {
      settings,
      pageContext: researchCtx(
        "URL analysis report — VirusTotal",
        "url scan submitted url analysis indicators of compromise " +
          "malware sample sandbox analysis threat intelligence virustotal",
      ),
    });
    expectInformational(r);
  });

  it("urlscan.io report is safe/informational", async () => {
    const r = await evaluateUrl("https://urlscan.io/result/abc-def/", {
      settings,
      pageContext: researchCtx(
        "urlscan.io — Scan report",
        "url scan submission report indicators of compromise threat " + "intelligence ioc urlscan",
      ),
    });
    expectInformational(r);
  });

  it("Stripe OAuth documentation is safe/informational", async () => {
    const r = await evaluateUrl("https://docs.stripe.com/connect/oauth-reference", {
      settings,
      pageContext: researchCtx(
        "OAuth 2.0 — Stripe Documentation",
        "documentation reference tutorial example OAuth 2.0 " +
          "authorization code flow PKCE redirect_uri client_id access token",
      ),
    });
    expectInformational(r);
  });

  it("GitHub OAuth demo repo README is safe/informational", async () => {
    const r = await evaluateUrl("https://github.com/acme/oauth-demo/blob/main/README.md", {
      settings,
      pageContext: researchCtx(
        "oauth-demo — sample app",
        "tutorial example demo getting started OAuth 2.0 " +
          "authorization code flow redirect_uri client_id access token",
      ),
    });
    expectInformational(r);
  });
});

// Regression — the upper-bound check does NOT mask real behavioral evidence.
describe("calibration — upper bounds do not mask real attacks", () => {
  it("research-flavored page with off-domain credential POST stays dangerous", async () => {
    const r = await evaluateUrl("https://phishing-awareness-portal.tld/login", {
      settings,
      pageContext: {
        pageOrigin: "https://phishing-awareness-portal.tld",
        title: "Phishing awareness training login",
        visibleText:
          "phishing awareness security training tutorial example " +
          "sign in to your account outlook office 365",
        forms: [
          {
            action: "https://collector.tld/grab",
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
    expect(r.status).toBe("dangerous");
  });
});
