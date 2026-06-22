import { describe, it, expect } from "vitest";
import {
  analyzeUrlReputation,
  ABUSED_TLDS,
  URL_SHORTENERS,
} from "../../extension/lib/urlReputation.js";

const ids = (r) => r.signals.map((s) => s.id);

describe("brand-domain-as-subdomain", () => {
  it("flags a real brand domain hidden in the subdomain", () => {
    const r = analyzeUrlReputation("https://paypal.com.account-verify.tk/login");
    expect(r.brandSubdomain).not.toBeNull();
    expect(r.brandSubdomain.brand).toBe("paypal.com");
    expect(ids(r)).toContain("brand-subdomain-spoof");
    expect(r.cap).toBeLessThanOrEqual(25);
  });
  it("flags microsoft hidden under an unrelated root", () => {
    const r = analyzeUrlReputation("https://login.microsoftonline.com.secure-tenant.xyz/");
    expect(r.brandSubdomain?.brand).toBe("microsoftonline.com");
  });
  it("does NOT flag the genuine brand domain", () => {
    expect(analyzeUrlReputation("https://www.paypal.com/signin").brandSubdomain).toBeNull();
    expect(analyzeUrlReputation("https://accounts.google.com/").brandSubdomain).toBeNull();
  });
  it("does NOT flag a brand-named path on its own site", () => {
    const r = analyzeUrlReputation("https://example.com/paypal-integration-guide");
    expect(r.brandSubdomain).toBeNull();
  });
});

describe("abused TLDs", () => {
  it("escalates a free-TLD login page", () => {
    const r = analyzeUrlReputation("https://secure-login.tk/", { hasAuthWorkflow: true });
    const sig = r.signals.find((s) => s.id === "abused-tld");
    expect(sig).toBeTruthy();
    expect(sig.severity).toBe("medium");
    expect(r.cap).toBeLessThanOrEqual(60);
  });
  it("keeps a free-TLD non-auth page low severity (no cap)", () => {
    const r = analyzeUrlReputation("https://myblog.xyz/post/1", { hasAuthWorkflow: false });
    const sig = r.signals.find((s) => s.id === "abused-tld");
    expect(sig.severity).toBe("low");
    expect(r.cap).toBeNull();
  });
  it("suppresses abused-TLD penalty on a trusted root", () => {
    const r = analyzeUrlReputation("https://foo.xyz/", {
      isTrustedRoot: true,
      hasAuthWorkflow: true,
    });
    expect(r.signals.find((s) => s.id === "abused-tld")).toBeUndefined();
  });
  it("known abused TLD set includes Freenom + .zip", () => {
    for (const t of ["tk", "ml", "ga", "cf", "gq", "zip", "xyz", "top"]) {
      expect(ABUSED_TLDS.has(t)).toBe(true);
    }
  });
});

describe("URL shorteners", () => {
  it("surfaces a shortener as informational", () => {
    const r = analyzeUrlReputation("https://bit.ly/abc123");
    expect(r.shortener).toBe(true);
    expect(ids(r)).toContain("url-shortener");
  });
  it("does not flag a normal domain", () => {
    expect(analyzeUrlReputation("https://news.ycombinator.com/").shortener).toBe(false);
  });
});

describe("phishy tokens", () => {
  it("flags account-lure wording", () => {
    const r = analyzeUrlReputation("https://random-host.com/secure-update/login", {
      hasAuthWorkflow: true,
    });
    expect(r.phishyToken).toBeTruthy();
    expect(ids(r)).toContain("phishy-token");
  });
});

describe("robustness", () => {
  it("returns empty result on garbage input", () => {
    const r = analyzeUrlReputation("not a url");
    expect(r.signals).toEqual([]);
    expect(r.brandSubdomain).toBeNull();
  });
  it("ignores non-http schemes", () => {
    expect(analyzeUrlReputation("ftp://paypal.com.evil.tk/").signals).toEqual([]);
  });
});
