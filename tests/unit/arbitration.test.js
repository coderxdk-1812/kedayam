import { describe, it, expect } from "vitest";
import { arbitrate } from "../../extension/lib/arbitration.js";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const empty = { lookalike: { match: null, confidence: 0 },
  clone: { confidence: 0 }, phishing: { confidence: 0 } };

describe("arbitrate (deterministic precedence)", () => {
  it("allowlist short-circuits ONLY when no behavioral evidence is present (Issue C-02)", () => {
    // Weak/visual heuristics under allowlist → no cap, no force.
    const r1 = arbitrate({ ...empty, allowlistRoot: true,
      lookalike: { confidence: 1 }, idnSpoof: true });
    expect(r1.cap).toBeNull();
    expect(r1.forceStatus).toBeNull();
    // Behavioral evidence (external POST) under allowlist → MUST escalate.
    const r2 = arbitrate({ ...empty, allowlistRoot: true,
      phishing: { credentialHarvest: true, externalFormPost: true } });
    expect(r2.forceStatus).toBe("dangerous");
    expect(r2.cap).toBeLessThanOrEqual(20);
  });

  it("forces dangerous on lookalike + credential harvest (unknown)", () => {
    const r = arbitrate({ ...empty,
      lookalike: { match: { brand: "paypal" }, confidence: 0.95 },
      phishing: { credentialHarvest: true } });
    expect(r.forceStatus).toBe("dangerous");
    expect(r.cap).toBeLessThanOrEqual(25);
  });

  it("forces dangerous on punycode + auth", () => {
    const r = arbitrate({ ...empty, idnSpoof: true,
      phishing: { credentialHarvest: true } });
    expect(r.forceStatus).toBe("dangerous");
    expect(r.cap).toBeLessThanOrEqual(25);
  });

  it("does NOT force dangerous on clone+auth alone — needs behavioral evidence", () => {
    const r = arbitrate({ ...empty, hasAuthWorkflow: true,
      clone: { confidence: 0.85 } });
    // Visual similarity alone must never be dangerous (G4 sanity rule).
    expect(r.forceStatus).not.toBe("dangerous");
  });

  it("forces dangerous on clone+auth WHEN paired with external POST", () => {
    const r = arbitrate({ ...empty, hasAuthWorkflow: true,
      clone: { confidence: 0.85 },
      phishing: { credentialHarvest: true, externalFormPost: true } });
    expect(r.forceStatus).toBe("dangerous");
  });

  it("does NOT cap trusted provider on lookalike alone (no behavioral evidence)", () => {
    const r = arbitrate({ ...empty, isTrustedProvider: true,
      lookalike: { confidence: 0.9 } });
    // Trusted root with no behavioral evidence → trust-floor short-circuit.
    expect(r.forceStatus).toBeNull();
    expect(r.trustFloor).toBeGreaterThanOrEqual(80);
  });

  it("DOES cap trusted provider when lookalike pairs with external POST", () => {
    const r = arbitrate({ ...empty, isTrustedProvider: true,
      lookalike: { confidence: 0.9 },
      phishing: { credentialHarvest: true, externalFormPost: true } });
    expect(r.forceStatus).toBe("dangerous");
  });

  it("uses tightest cap when multiple rules match", () => {
    const r = arbitrate({ ...empty, idnSpoof: true,
      phishing: { credentialHarvest: true, externalFormPost: true } });
    // external-post rule (cap 20) should win over idn-creds (cap 25)
    expect(r.cap).toBeLessThanOrEqual(20);
    expect(r.forceStatus).toBe("dangerous");
  });
});

describe("trust calibration (earn-trust model)", () => {
  const settings = { detection: { sensitivity: "balanced" },
    apiKeys: {}, allowlist: [] };

  it("unknown HTTPS site lands in informational band, not 100", async () => {
    const r = await evaluateUrl("https://random-blog-12345.tld/", { settings });
    expect(r.score).toBeGreaterThanOrEqual(50);
    expect(r.score).toBeLessThan(75);
  });

  it("unknown auth page never enters safe band", async () => {
    const r = await evaluateUrl("https://random-portal-99.tld/", {
      settings,
      pageContext: { pageOrigin: "https://random-portal-99.tld",
        title: "Login", visibleText: "sign in",
        hasPasswordField: true,
        forms: [{ action: "/login", method: "post", hasPassword: true,
          hasEmailLike: true, hasOtp: false, hiddenCount: 0,
          fieldsCount: 2, insideIframe: false }] },
    });
    expect(r.status).not.toBe("safe");
    expect(r.score).toBeLessThanOrEqual(70);
  });

  it("punycode + auth flow is at least suspicious, not safe", async () => {
    // xn--80ak6aa92e.com (apple.com homoglyph) with login form
    const r = await evaluateUrl("https://xn--pple-43d.com/signin", {
      settings,
      pageContext: { pageOrigin: "https://xn--pple-43d.com",
        title: "Sign in", visibleText: "sign in",
        hasPasswordField: true,
        forms: [{ action: "/login", method: "post", hasPassword: true,
          hasEmailLike: true, hasOtp: false, hiddenCount: 0,
          fieldsCount: 2, insideIframe: false }] },
    });
    expect(r.status).not.toBe("safe");
    expect(r.score).toBeLessThanOrEqual(30);
  });

  it("clone with off-domain credential POST is dangerous", async () => {
    const r = await evaluateUrl("https://fake-bank.tld/", {
      settings,
      pageContext: {
        pageOrigin: "https://fake-bank.tld", title: "Login",
        visibleText: "sign in to your account",
        hasPasswordField: true,
        favicon: "https://chase.com/favicon.ico",
        scripts: [], styles: [],
        images: ["https://chase.com/logo.png"],
        forms: [{ action: "https://collector.tld/post", method: "post",
          hasPassword: true, hasEmailLike: true, hasOtp: false,
          hiddenCount: 0, fieldsCount: 2, insideIframe: false }],
      },
    });
    expect(r.status).toBe("dangerous");
    expect(r.score).toBeLessThanOrEqual(20);
  });

  it("trust adds are surfaced for explainability", async () => {
    const r = await evaluateUrl("https://example.com/", { settings });
    expect(r.trustAdds.length).toBeGreaterThan(0);
    expect(r.trustAdds.some((s) => s.id === "https-trust")).toBe(true);
    expect(r.trustAdds.some((s) => s.id === "known-reputable")).toBe(true);
  });

  it("arbitration result is exposed on the verdict", async () => {
    const r = await evaluateUrl("https://office365-secure-login.tld/", {
      settings,
      pageContext: {
        pageOrigin: "https://office365-secure-login.tld",
        title: "Sign in to Microsoft", visibleText: "outlook office 365",
        hasPasswordField: true,
        forms: [{ action: "/login", method: "post", hasPassword: true,
          hasEmailLike: true, hasOtp: false, hiddenCount: 0,
          fieldsCount: 2, insideIframe: false }],
      },
    });
    expect(r.arbitration).toBeDefined();
    expect(r.arbitration.rules.length).toBeGreaterThan(0);
    expect(r.arbitration.forceStatus).toBe("dangerous");
  });
});
