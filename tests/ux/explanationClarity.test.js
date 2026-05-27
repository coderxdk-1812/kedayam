// UX regression — user-facing explanations must read like plain English.
//
// These assertions defend against drift in three directions:
//   1. Internal jargon (acronyms, rule-id shapes) leaking to users.
//   2. Bullets / headlines growing unboundedly long over time.
//   3. Empty/blank user-facing fields when a real verdict is in hand.
// The numeric scoring engine is untouched — this only governs the strings
// the popup and warning UIs render.

import { describe, it, expect } from "vitest";
import { explainVerdict } from "../../extension/lib/explanation.js";
import { isUserVisible, extractVisibleText } from "../../extension/lib/visibleText.js";

const MAX_USER_STR = 220; // mirrors explanation.js
const JARGON_TOKENS = [
  "CSP", "OAuth issuer", "eTLD+1", "JWT", "XSS", "CSRF", "MITM", "AiTM",
  "SAML", "JOSE", "HSTS", "TLS handshake", "CORS", "PKCE",
];
const RULE_ID_SHAPE = /\b[a-z]+(?:-[a-z]+){2,}\b/; // e.g. "auth-flow-anomaly"

function makeVerdict(status, extra = {}) {
  return {
    url: "https://example.test/", host: "example.test", root: "example",
    score: status === "dangerous" ? 15 : status === "suspicious" ? 55 : 92,
    status,
    phishingConfidence: status === "dangerous" ? 0.9 : 0.2,
    cloneConfidence: 0,
    signals: [], trustAdds: [], arbitration: { rules: [] },
    ...extra,
  };
}

describe("explainVerdict — clarity & length bounds", () => {
  it("clamps every user-facing string to a readable length", () => {
    const long = "x".repeat(2000);
    const x = explainVerdict(makeVerdict("dangerous", {
      signals: [
        { id: "lookalike", title: long, severity: "critical",
          category: "identity", contribution: -50 },
      ],
      arbitration: { rules: [{ id: "lookalike-creds", cap: 25, reason: long }] },
    }));
    expect(x.headline.length).toBeLessThanOrEqual(MAX_USER_STR);
    expect(x.summary.length).toBeLessThanOrEqual(MAX_USER_STR);
    expect(x.recommendation.length).toBeLessThanOrEqual(MAX_USER_STR);
    for (const b of x.bullets) expect(b.length).toBeLessThanOrEqual(MAX_USER_STR);
  });

  it("never leaks internal jargon or raw rule-id strings to bullets", () => {
    const x = explainVerdict(makeVerdict("dangerous", {
      signals: [
        // Title intentionally jargon-y to mimic a future internal label
        // that didn't get a curated translation yet.
        { id: "future-internal-signal", title: "AiTM CSP downgrade detected",
          severity: "high", category: "behavior", contribution: -30 },
      ],
      arbitration: { rules: [
        { id: "novel-internal-rule", cap: 40,
          reason: "credential-relay-evidence with SAML-style anomaly" },
      ] },
    }));
    const allText = [x.headline, x.summary, x.recommendation, ...x.bullets].join(" ");
    for (const tok of JARGON_TOKENS) {
      expect(allText).not.toContain(tok);
    }
    for (const b of x.bullets) {
      expect(RULE_ID_SHAPE.test(b)).toBe(false);
      expect(b).not.toMatch(/^[a-z]+(?:-[a-z]+)+$/); // never a bare rule id
    }
    // It also doesn't leak the raw rule.id "novel-internal-rule".
    expect(allText).not.toContain("novel-internal-rule");
  });

  it("separates tone by severity (dangerous urgent, safe reassuring)", () => {
    const d = explainVerdict(makeVerdict("dangerous"));
    const s = explainVerdict(makeVerdict("suspicious"));
    const ok = explainVerdict(makeVerdict("safe"));

    expect(d.headline.toLowerCase()).toContain("dangerous");
    expect(d.recommendation.toLowerCase()).toMatch(/close|don't|avoid/);

    expect(s.headline.toLowerCase()).not.toContain("dangerous");
    expect(s.recommendation.toLowerCase()).toMatch(/careful|leave|only continue/);

    expect(ok.headline.toLowerCase()).toContain("safe");
    expect(ok.recommendation.toLowerCase()).toMatch(/continue/);
  });

  it("produces non-empty headline/summary/recommendation for every status", () => {
    for (const status of ["safe", "suspicious", "dangerous"]) {
      const x = explainVerdict(makeVerdict(status));
      expect(x.headline.trim().length).toBeGreaterThan(0);
      expect(x.summary.trim().length).toBeGreaterThan(0);
      expect(x.recommendation.trim().length).toBeGreaterThan(0);
    }
  });

  it("renders curated plain text for known signal IDs", () => {
    const x = explainVerdict(makeVerdict("dangerous", {
      signals: [
        { id: "external-form-post", title: "External form post",
          severity: "critical", category: "behavior", contribution: -45 },
      ],
    }));
    const first = x.contributingRisks[0];
    expect(first.plain.toLowerCase()).toContain("different website");
    // Must not be a single-word id or a token-shaped string.
    expect(first.plain).not.toMatch(/^[a-z-]+$/);
  });
});

// ----- hidden DOM exclusion (visibleText normalization) ---------------

function fakeEl({
  tag = "P", text = "", aria = null, parent = null,
  style = { display: "block", visibility: "visible", opacity: "1" },
  rect = { width: 100, height: 20 },
} = {}) {
  const el = {
    tagName: tag, textContent: text,
    _aria: aria, _parent: parent,
    getBoundingClientRect: () => rect,
    closest(sel) {
      if (sel === '[aria-hidden="true"]') {
        let cur = this;
        while (cur) { if (cur._aria === "true") return cur; cur = cur._parent; }
      }
      return null;
    },
  };
  return el;
}
const styleFor = (map) => (el) => map.get(el) || {
  display: "block", visibility: "visible", opacity: "1",
};

describe("visibleText normalization — hidden DOM excluded", () => {
  it("rejects display:none / visibility:hidden / opacity:0 elements", () => {
    const a = fakeEl({ text: "shown" });
    const b = fakeEl({ text: "display-none" });
    const c = fakeEl({ text: "vis-hidden" });
    const d = fakeEl({ text: "opacity-0" });
    const map = new Map([
      [b, { display: "none", visibility: "visible", opacity: "1" }],
      [c, { display: "block", visibility: "hidden", opacity: "1" }],
      [d, { display: "block", visibility: "visible", opacity: "0" }],
    ]);
    const out = extractVisibleText([a, b, c, d], { getStyle: styleFor(map) });
    expect(out).toContain("shown");
    expect(out).not.toContain("display-none");
    expect(out).not.toContain("vis-hidden");
    expect(out).not.toContain("opacity-0");
  });

  it("rejects aria-hidden subtrees and script/style/template/noscript tags", () => {
    const ariaParent = fakeEl({ tag: "DIV", aria: "true" });
    const inAriaHidden = fakeEl({ text: "aria-trap", parent: ariaParent });
    const script = fakeEl({ tag: "SCRIPT", text: "evil()" });
    const style = fakeEl({ tag: "STYLE", text: "body{}" });
    const visible = fakeEl({ text: "real label" });
    const out = extractVisibleText([inAriaHidden, script, style, visible],
      { getStyle: styleFor(new Map()) });
    expect(out).toContain("real label");
    expect(out).not.toContain("aria-trap");
    expect(out).not.toContain("evil()");
    expect(out).not.toContain("body{}");
  });

  it("rejects zero-area off-screen traps but keeps small visible labels", () => {
    const trap = fakeEl({ text: "off-screen", rect: { width: 0, height: 0 } });
    const tiny = fakeEl({ text: "tiny-but-visible", rect: { width: 1, height: 1 } });
    const out = extractVisibleText([trap, tiny], { getStyle: styleFor(new Map()) });
    expect(out).not.toContain("off-screen");
    expect(out).toContain("tiny-but-visible");
  });

  it("includes the document title when supplied", () => {
    const out = extractVisibleText([], {
      titleText: "Sign in to Acme", getStyle: styleFor(new Map()),
    });
    expect(out).toBe("Sign in to Acme");
  });

  it("bounds the output length", () => {
    const big = fakeEl({ text: "x".repeat(10000) });
    const out = extractVisibleText([big], {
      maxLen: 4000, getStyle: styleFor(new Map()),
    });
    expect(out.length).toBeLessThanOrEqual(4000);
  });

  it("isUserVisible defaults to true on malformed input (no over-filtering)", () => {
    expect(isUserVisible({ tagName: "DIV", textContent: "ok" },
      () => null)).toBe(true);
    // Missing tagName → not an element → rejected.
    expect(isUserVisible({}, () => null)).toBe(false);
  });
});
