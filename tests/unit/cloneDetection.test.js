import { describe, it, expect } from "vitest";
import { analyzeClone } from "../../extension/lib/cloneDetection.js";

describe("analyzeClone", () => {
  it("returns 0 confidence for first-party assets", () => {
    const r = analyzeClone({
      pageOrigin: "https://example.com",
      scripts: ["https://example.com/a.js", "https://example.com/b.js"],
      styles: ["https://example.com/x.css"],
      images: ["https://example.com/logo.png"],
    });
    expect(r.confidence).toBe(0);
  });

  it("ignores trusted CDNs when scoring", () => {
    const r = analyzeClone({
      pageOrigin: "https://example.com",
      scripts: ["https://cdn.jsdelivr.net/npm/react.js"],
      styles: ["https://fonts.googleapis.com/css?family=Inter"],
      images: [],
    });
    expect(r.confidence).toBe(0);
    expect(r.crossOriginRatio).toBe(0);
  });

  it("records favicon mismatch as a single signal but does NOT raise confidence alone", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker-site.tld",
      scripts: [], styles: [], images: [],
      favicon: "https://paypal.com/favicon.ico",
    });
    expect(r.faviconMismatch).toBe(true);
    expect(r.signalCount).toBe(1);
    expect(r.confidence).toBe(0);
  });

  it("records brand-image theft as a single signal but does NOT raise confidence alone", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker-site.tld",
      scripts: [], styles: [],
      images: ["https://paypal.com/assets/logo.png"],
    });
    expect(r.brandImageMismatch).toBe(true);
    expect(r.signalCount).toBe(1);
    expect(r.confidence).toBe(0);
    expect(r.reasons.some((x) => x.includes("paypal"))).toBe(true);
  });

  it("raises confidence only when 2+ independent signals agree", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker-site.tld",
      scripts: [], styles: [],
      images: ["https://paypal.com/logo.png"],
      favicon: "https://paypal.com/favicon.ico",
    });
    expect(r.signalCount).toBeGreaterThanOrEqual(2);
    expect(r.confidence).toBeGreaterThan(0);
  });

  it("does NOT count high cross-origin asset ratio as a signal", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker.tld",
      scripts: [
        "https://evil1.tld/a.js", "https://evil2.tld/b.js",
        "https://evil3.tld/c.js", "https://evil4.tld/d.js",
      ],
      styles: [], images: [],
    });
    expect(r.crossOriginRatio).toBeGreaterThan(0.5);
    expect(r.signalCount).toBe(0);
    expect(r.confidence).toBe(0);
  });

  it("never counts shared infrastructure as brand signal even if listed on Googleapis", () => {
    const r = analyzeClone({
      pageOrigin: "https://example.tld",
      scripts: ["https://www.googletagmanager.com/gtag/js"],
      styles: ["https://fonts.googleapis.com/css2"],
      images: ["https://www.gstatic.com/images/icons/material/system/2x/check.png"],
      favicon: "https://www.gstatic.com/favicon.ico",
    });
    expect(r.faviconMismatch).toBe(false);
    expect(r.brandImageMismatch).toBe(false);
    expect(r.confidence).toBe(0);
  });

  it("clone alone (no phishing corroboration) caps contribution low", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker.tld",
      scripts: [], styles: [],
      images: ["https://paypal.com/logo.png"],
      favicon: "https://paypal.com/favicon.ico",
    });
    // No phishing in ctx → informational score only.
    expect(r.score).toBeLessThanOrEqual(10);
  });

  it("clone + phishing corroboration produces a meaningful contribution", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker.tld",
      scripts: [], styles: [],
      images: ["https://paypal.com/logo.png"],
      favicon: "https://paypal.com/favicon.ico",
      phishing: { credentialHarvest: true, externalFormPost: true },
    });
    expect(r.score).toBeGreaterThan(10);
  });

  it("each scan is independent — pure function, no cross-call state", () => {
    const a = analyzeClone({
      pageOrigin: "https://attacker.tld", scripts: [], styles: [],
      images: ["https://paypal.com/logo.png"],
      favicon: "https://paypal.com/favicon.ico",
      phishing: { credentialHarvest: true },
    });
    const b = analyzeClone({
      pageOrigin: "https://example.com",
      scripts: [], styles: [], images: [],
    });
    expect(b.confidence).toBe(0);
    expect(b.signalCount).toBe(0);
    expect(b.reasons).toEqual([]);
    expect(a.confidence).toBeGreaterThan(0); // a unaffected
  });
});
