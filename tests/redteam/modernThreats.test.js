import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";
import { BLOCKLIST_SEED } from "../../extension/lib/rules/blocklistSeed.js";

const baseSettings = { detection: { sensitivity: "balanced" } };

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

describe("brand-domain-as-subdomain phishing", () => {
  it("rates a credential page on paypal.com.<evil> as dangerous", async () => {
    const url = "https://paypal.com.account-verify.tk/login";
    const r = await evaluateUrl(url, {
      settings: baseSettings,
      pageContext: loginContext("https://paypal.com.account-verify.tk"),
    });
    expect(r.urlReputation.brandSubdomain).not.toBeNull();
    expect(r.status).toBe("dangerous");
    expect(r.score).toBeLessThanOrEqual(25);
  });
});

describe("freeware threat blocklist", () => {
  it("rates a bundled-blocklist host as dangerous with no API key", async () => {
    const host = BLOCKLIST_SEED[0];
    const r = await evaluateUrl(`https://${host}/`, { settings: baseSettings });
    expect(r.threatBlocklist.match).toBe(true);
    expect(r.status).toBe("dangerous");
  });
  it("matches a subdomain of an opt-in feed entry", async () => {
    const r = await evaluateUrl("https://login.evil-kit.cc/", {
      settings: baseSettings,
      blocklistExtra: new Set(["evil-kit.cc"]),
    });
    expect(r.threatBlocklist.match).toBe(true);
    expect(r.status).toBe("dangerous");
  });
  it("can be disabled via settings", async () => {
    const host = BLOCKLIST_SEED[0];
    const r = await evaluateUrl(`https://${host}/`, {
      settings: { detection: { sensitivity: "balanced", localBlocklist: false } },
    });
    expect(r.threatBlocklist.match).toBe(false);
  });
});

describe("abused-TLD credential pages", () => {
  it("never rates a free-TLD login as safe", async () => {
    const r = await evaluateUrl("https://account-portal.tk/login", {
      settings: baseSettings,
      pageContext: loginContext("https://account-portal.tk"),
    });
    expect(r.status).not.toBe("safe");
    expect(r.score).toBeLessThanOrEqual(60);
  });
  it("keeps a free-TLD blog (no auth) usable — no dangerous verdict", async () => {
    const r = await evaluateUrl("https://my-notes.xyz/post/hello", { settings: baseSettings });
    expect(r.status).not.toBe("dangerous");
  });
});

describe("false-positive guard: legitimate sites stay safe", () => {
  it("github.com login is safe", async () => {
    const r = await evaluateUrl("https://github.com/login", {
      settings: baseSettings,
      pageContext: loginContext("https://github.com"),
    });
    expect(r.status).toBe("safe");
  });
  it("google.com is safe", async () => {
    const r = await evaluateUrl("https://www.google.com/", { settings: baseSettings });
    expect(r.status).toBe("safe");
  });
  it("a normal .xyz startup landing page is not dangerous", async () => {
    const r = await evaluateUrl("https://linear.xyz/", { settings: baseSettings });
    expect(r.status).not.toBe("dangerous");
  });
});
