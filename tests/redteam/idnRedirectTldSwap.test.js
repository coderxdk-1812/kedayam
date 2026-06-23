import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const settings = { detection: { sensitivity: "balanced" } };

function loginContext(origin) {
  return {
    pageOrigin: origin,
    title: "Sign in",
    visibleText: "Sign in to continue",
    hasPasswordField: true,
    forms: [
      {
        action: origin + "/login",
        method: "post",
        hasPassword: true,
        hasEmailLike: true,
        hasOtp: false,
        hiddenCount: 0,
        fieldsCount: 2,
        insideIframe: false,
      },
    ],
    oauthButtons: [],
  };
}

describe("IDN mixed-script hostnames", () => {
  it("detects a Cyrillic/Latin mixed host through the engine", async () => {
    // Node's URL serializes this to punycode; the engine decodes it back.
    const r = await evaluateUrl("https://аpple.com/", { settings });
    expect(r.confusable.mixedScript).toBe(true);
    expect(r.status).not.toBe("safe");
  });
});

describe("open-redirect laundering", () => {
  it("surfaces an external redirect parameter on the result", async () => {
    const r = await evaluateUrl("https://news-portal.cc/out?url=https://evil.tld/login", {
      settings,
    });
    expect(r.openRedirect.external).toBe(true);
    expect(r.openRedirect.targetHost).toBe("evil.tld");
  });
  it("does not penalize same-site redirects", async () => {
    const r = await evaluateUrl("https://example.com/go?next=https://example.com/home", {
      settings,
    });
    expect(r.openRedirect.external).toBe(false);
  });
});

describe("TLD-swap credential pages", () => {
  it("rates a wrong-TLD brand login as not safe", async () => {
    const r = await evaluateUrl("https://paypal.co/login", {
      settings,
      pageContext: loginContext("https://paypal.co"),
    });
    expect(r.urlReputation.tldSwap).not.toBeNull();
    expect(r.status).not.toBe("safe");
  });
});

describe("false-positive guard for new layers", () => {
  it("a legitimate site using a ?url= redirect to itself stays safe", async () => {
    const r = await evaluateUrl("https://github.com/login?return_to=https://github.com/dashboard", {
      settings,
    });
    expect(r.status).toBe("safe");
  });
  it("a normal multi-language site is not flagged mixed-script", async () => {
    const r = await evaluateUrl("https://en.wikipedia.org/wiki/Main_Page", { settings });
    expect(r.confusable.mixedScript).toBe(false);
    expect(r.status).toBe("safe");
  });
});
