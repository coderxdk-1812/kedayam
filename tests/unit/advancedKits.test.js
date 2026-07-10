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
  { file: "reverse-proxy-aitm.html", origin: "https://office365-secure.evilhost.cc" },
  { file: "fake-browser-update.html", origin: "https://chrome-update.evilhost.cc" },
  { file: "fake-extension-install.html", origin: "https://secure-extension.evilhost.cc" },
];

function ctxOf(html, origin) {
  const dom = new JSDOM(html, { url: origin });
  const doc = dom.window.document;
  const forms = Array.from(doc.querySelectorAll("form")).map((f) => {
    const inputs = Array.from(f.querySelectorAll("input"));
    return {
      action: f.getAttribute("action") || "",
      method: f.getAttribute("method") || "post",
      hasPassword: inputs.some((i) => (i.type || "").toLowerCase() === "password"),
      hasEmailLike: inputs.some(
        (i) =>
          (i.type || "").toLowerCase() === "email" ||
          /email|user|login/.test(`${i.name || ""}${i.id || ""}`),
      ),
      hasOtp: false,
      hiddenCount: 0,
      fieldsCount: inputs.length,
      insideIframe: false,
    };
  });
  return {
    pageOrigin: origin,
    title: doc.title || "",
    visibleText: (doc.body?.textContent || "").trim().slice(0, 4000),
    forms,
    hasPasswordField: !!doc.querySelector("input[type=password]"),
    oauthButtons: [],
  };
}

describe("advanced phishing kit fixtures", () => {
  for (const c of CASES) {
    it(`${c.file} → dangerous`, () => {
      const html = readFileSync(join(FIX, c.file), "utf8");
      const ctx = ctxOf(html, c.origin);
      const phishing = analyzePhishing(ctx);
      const clone = analyzeClone(ctx);
      const authLayout = analyzeAuthLayout(ctx);
      const arb = arbitrate({
        allowlistRoot: false,
        isReputableRoot: false,
        isTrustedProvider: false,
        hasAuthWorkflow: true,
        lookalike: { match: null, confidence: 0 },
        idnSpoof: false,
        clone,
        phishing,
        authLayout,
        hiddenLoginOverlay: false,
        emailFirstFlow: false,
        mfaOnly: false,
      });
      expect(arb.forceStatus).toBe("dangerous");
    });
  }
});
