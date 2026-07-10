import { describe, it, expect } from "vitest";
import {
  classifyPhishing,
  extractFeatures,
  _internal,
} from "../../extension/lib/phishingClassifier.js";

describe("phishingClassifier — false-positive guards (must stay benign)", () => {
  const BENIGN = [
    "https://github.com/anthropics/claude",
    "https://www.google.com/search?q=hi",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://app.notion.so/login", // has a lure token but ordinary shape
    "https://my-secure-bank.co.uk/", // hyphens + "secure" but reputable shape
    "https://onlinebanking.hdfcbank.com/",
    "https://startup.xyz/", // a free-TLD blog with nothing else phishy
  ];
  for (const url of BENIGN) {
    it(`rates ${url} benign`, () => {
      const r = classifyPhishing(url);
      expect(r.label).toBe("benign");
      expect(r.probability).toBeLessThan(0.55);
      expect(r.signals).toHaveLength(0);
    });
  }

  it("never flags a trusted root even with a password form", () => {
    const r = classifyPhishing("https://accounts.google.com/signin", {
      isTrustedRoot: true,
      pageContext: {
        hasPasswordField: true,
        forms: [{ action: "https://evil.tk", hasPassword: true }],
      },
    });
    expect(r.label).toBe("benign");
    expect(r.probability).toBe(0);
    expect(r.signals).toHaveLength(0);
  });
});

describe("phishingClassifier — true positives", () => {
  it("flags a brand-in-subdomain kit on an abused TLD with an off-origin login form", () => {
    const r = classifyPhishing("http://paypal.com.secure-login.tk/verify", {
      pageContext: {
        pageOrigin: "http://paypal.com.secure-login.tk",
        hasPasswordField: true,
        forms: [
          { action: "http://harvest.evil.tk/collect", hasPassword: true, hasEmailLike: true },
        ],
      },
    });
    expect(r.label).toBe("phishing");
    expect(r.probability).toBeGreaterThanOrEqual(0.8);
    expect(r.signals[0].id).toBe("ml-phishing-structure");
    expect(r.signals[0].severity).toBe("critical");
  });

  it("flags a credential-lure host on a free TLD from the URL alone (no DOM)", () => {
    const r = classifyPhishing("http://verify-account-secure.tk/login");
    expect(["suspicious", "phishing"]).toContain(r.label);
    expect(r.signals.length).toBeGreaterThan(0);
  });

  it("is explainable — surfaces the top contributing features", () => {
    const r = classifyPhishing("http://paypal.com.secure-login.tk/verify");
    expect(r.topContributors.length).toBeGreaterThan(0);
    expect(r.topContributors[0]).toHaveProperty("feature");
    expect(r.topContributors[0]).toHaveProperty("contribution");
  });
});

describe("phishingClassifier — feature extraction", () => {
  it("detects punycode, abused TLD, digits and deep subdomains", () => {
    const f = extractFeatures("http://xn--pple-43d.a1b2c3.deep.sub.evil.tk/");
    expect(f.punycode).toBe(1);
    expect(f.abusedTld).toBe(1);
    expect(f.notHttps).toBe(1);
    expect(f.hostDigitsRatio).toBeGreaterThan(0);
    expect(f.manySubdomains).toBeGreaterThan(0);
  });

  it("detects an off-origin credential form from page context", () => {
    const f = extractFeatures("https://kit.example/login", {
      pageOrigin: "https://kit.example",
      forms: [{ action: "https://collector.tk/x", hasPassword: true }],
    });
    expect(f.crossOriginForm).toBe(1);
  });

  it("detects obfuscated payload blobs in sampled text", () => {
    const blob = "A".repeat(200);
    const f = extractFeatures("https://x.example/", { textSample: `var p="${blob}"` });
    expect(f.obfuscation).toBe(1);
  });

  it("returns an all-zero vector for an invalid URL", () => {
    const f = extractFeatures("not a url");
    expect(Object.values(f).every((v) => v === 0)).toBe(true);
  });
});

describe("phishingClassifier — model internals", () => {
  it("exposes a monotonic sigmoid", () => {
    expect(_internal.sigmoid(0)).toBeCloseTo(0.5, 5);
    expect(_internal.sigmoid(10)).toBeGreaterThan(_internal.sigmoid(-10));
  });
});
