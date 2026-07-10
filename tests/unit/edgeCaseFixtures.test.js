// Kedayam — edge-case fixture validation.
//
// Walks the additional adversarial fixtures (banking MFA, SSO redirect,
// federated IdP, CAPTCHA-wrapped, QR login) and asserts the arbitration
// engine flags them as `dangerous`. These are deliberately *harder* than
// the core replay suite and act as a regression guard on edge cases.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";
import { analyzeClone } from "../../extension/lib/cloneDetection.js";
import { analyzeAuthLayout } from "../../extension/lib/authLayout.js";
import { arbitrate } from "../../extension/lib/arbitration.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIX = join(here, "../fixtures/phishing");

const CASES = [
  { file: "banking-mfa.html", origin: "https://securebank-verify.example.cc" },
  { file: "sso-redirect.html", origin: "https://office365-portal.example.tld" },
  { file: "federated-idp.html", origin: "https://login-aggregator.example.tld" },
  { file: "captcha-wrap.html", origin: "https://account-verify.example.cc" },
  { file: "qr-login.html", origin: "https://wa-web.example.tld" },
];

function buildCtx(html, origin) {
  const dom = new JSDOM(html, { url: origin });
  const doc = dom.window.document;
  const forms = Array.from(doc.querySelectorAll("form")).map((f) => {
    const inputs = Array.from(f.querySelectorAll("input"));
    const hasPassword = inputs.some((i) => (i.type || "").toLowerCase() === "password");
    const hasEmailLike = inputs.some((i) => {
      const t = (i.type || "").toLowerCase();
      const n = `${i.name || ""} ${i.id || ""} ${i.autocomplete || ""}`.toLowerCase();
      return t === "email" || /email|user(name)?|login/.test(n);
    });
    const hasOtp = inputs.some((i) => {
      const n = `${i.name || ""} ${i.id || ""} ${i.autocomplete || ""}`.toLowerCase();
      return /otp|one[-_ ]?time|2fa|mfa|verification[-_ ]?code/.test(n);
    });
    return {
      action: f.getAttribute("action") || "",
      method: f.getAttribute("method") || "post",
      hasPassword,
      hasEmailLike,
      hasOtp,
      hiddenCount: inputs.filter((i) => (i.type || "").toLowerCase() === "hidden").length,
      fieldsCount: inputs.length,
      insideIframe: false,
    };
  });
  return {
    pageOrigin: origin,
    title: doc.title || "",
    visibleText: (doc.body?.textContent || "").replace(/\s+/g, " ").trim().slice(0, 4000),
    forms,
    hasPasswordField: !!doc.querySelector("input[type=password]"),
    oauthButtons: Array.from(doc.querySelectorAll("button"))
      .map((e) => (e.textContent || "").match(/continue with (google|microsoft|apple)/i)?.[1])
      .filter(Boolean),
  };
}

describe("edge-case phishing fixtures", () => {
  for (const c of CASES) {
    it(`${c.file} → dangerous`, () => {
      const html = readFileSync(join(FIX, c.file), "utf8");
      const ctx = buildCtx(html, c.origin);
      const phishing = analyzePhishing(ctx);
      const clone = analyzeClone(ctx);
      const authLayout = analyzeAuthLayout(ctx);
      const arb = arbitrate({
        allowlistRoot: false,
        isReputableRoot: false,
        isTrustedProvider: false,
        hasAuthWorkflow: phishing.credentialHarvest || ctx.hasPasswordField,
        lookalike: { match: null, confidence: 0 },
        idnSpoof: false,
        clone,
        phishing,
        authLayout,
        hiddenLoginOverlay: false,
        emailFirstFlow: (phishing.forms || []).some(
          (f) => f.hasEmailLike && !f.hasPassword && (f.fieldsCount || 0) <= 4,
        ),
        mfaOnly:
          (phishing.forms || []).length > 0 &&
          (phishing.forms || []).every((f) => f.hasOtp && !f.hasPassword),
      });
      expect(arb.forceStatus).toBe("dangerous");
    });
  }
});
