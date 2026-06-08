// Regression — clone detection accuracy stabilisation patch.
//
// Locks in the calibration:
//  - Top legitimate domains never trigger clone confidence.
//  - Infrastructure / shared CDN usage never raises clone confidence.
//  - Clone confidence requires ≥2 independent signals.
//  - Asset overlap alone is never sufficient.

import { describe, it, expect } from "vitest";
import { analyzeClone } from "../../extension/lib/cloneDetection.js";

const SAFE_DOMAINS = [
  "https://github.com",
  "https://www.google.com",
  "https://www.microsoft.com",
  "https://www.notion.so",
  "https://slack.com",
  "https://www.apple.com",
  "https://www.amazon.com",
  "https://www.youtube.com",
  "https://www.facebook.com",
  "https://www.instagram.com",
  "https://www.linkedin.com",
  "https://x.com",
  "https://www.netflix.com",
  "https://www.dropbox.com",
  "https://www.adobe.com",
  "https://www.cloudflare.com",
  "https://www.wikipedia.org",
  "https://www.reddit.com",
  "https://www.spotify.com",
  "https://www.airbnb.com",
  "https://www.stackoverflow.com",
  "https://kedayam.lovable.app",
];

// Typical mix of infrastructure assets that a legitimate site might load.
const REALISTIC_ASSETS = {
  scripts: [
    "https://www.googletagmanager.com/gtag/js?id=GA-XXX",
    "https://cdn.jsdelivr.net/npm/lodash@4/lodash.min.js",
    "https://unpkg.com/react@18/umd/react.production.min.js",
    "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
  ],
  styles: [
    "https://fonts.googleapis.com/css2?family=Inter",
    "https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css",
  ],
  images: [
    "https://www.gstatic.com/icons/material/check.png",
    "https://images.unsplash.com/photo-123",
  ],
  favicon: "/favicon.ico",
};

describe("clone detection accuracy — legitimate domains", () => {
  for (const origin of SAFE_DOMAINS) {
    it(`does not flag ${origin} as a clone`, () => {
      const r = analyzeClone({ pageOrigin: origin, ...REALISTIC_ASSETS });
      expect(r.confidence).toBe(0);
      expect(r.signalCount).toBeLessThan(2);
    });
  }
});

describe("clone detection accuracy — infrastructure exclusion", () => {
  it("treats fonts.googleapis / gstatic / cloudflare as infrastructure", () => {
    const r = analyzeClone({
      pageOrigin: "https://example.com",
      scripts: [
        "https://www.googletagmanager.com/gtag/js",
        "https://cdnjs.cloudflare.com/ajax/libs/foo.js",
      ],
      styles: ["https://fonts.googleapis.com/css2"],
      images: ["https://www.gstatic.com/icons/foo.png"],
      favicon: "https://www.gstatic.com/favicon.ico",
    });
    expect(r.faviconMismatch).toBe(false);
    expect(r.brandImageMismatch).toBe(false);
    expect(r.confidence).toBe(0);
  });

  it("100% cross-origin assets from CDNs never raises confidence", () => {
    const r = analyzeClone({
      pageOrigin: "https://example.com",
      scripts: [
        "https://cdn.jsdelivr.net/a.js",
        "https://unpkg.com/b.js",
        "https://cdnjs.cloudflare.com/c.js",
      ],
      styles: [], images: [],
    });
    expect(r.crossOriginRatio).toBe(0);
    expect(r.confidence).toBe(0);
  });
});

describe("clone detection accuracy — multi-signal gating", () => {
  it("single signal (favicon only) never raises confidence", () => {
    const r = analyzeClone({
      pageOrigin: "https://random.tld",
      scripts: [], styles: [], images: [],
      favicon: "https://paypal.com/favicon.ico",
    });
    expect(r.signalCount).toBe(1);
    expect(r.confidence).toBe(0);
  });

  it("single signal (brand image only) never raises confidence", () => {
    const r = analyzeClone({
      pageOrigin: "https://random.tld",
      scripts: [], styles: [],
      images: ["https://chase.com/logo.png"],
    });
    expect(r.signalCount).toBe(1);
    expect(r.confidence).toBe(0);
  });

  it("two signals (favicon + brand image) raises confidence", () => {
    const r = analyzeClone({
      pageOrigin: "https://random.tld",
      scripts: [], styles: [],
      images: ["https://paypal.com/logo.png"],
      favicon: "https://paypal.com/favicon.ico",
    });
    expect(r.signalCount).toBeGreaterThanOrEqual(2);
    expect(r.confidence).toBeGreaterThan(0);
  });

  it("clone alone (no phishing corroboration) cannot push dangerous", () => {
    const r = analyzeClone({
      pageOrigin: "https://random.tld",
      scripts: [], styles: [],
      images: ["https://paypal.com/logo.png"],
      favicon: "https://paypal.com/favicon.ico",
    });
    expect(r.score).toBeLessThanOrEqual(10);
  });
});

describe("clone detection — per-scan isolation", () => {
  it("does not leak state between scans", () => {
    const scan1 = analyzeClone({
      pageOrigin: "https://random.tld",
      scripts: [], styles: [],
      images: ["https://paypal.com/logo.png"],
      favicon: "https://paypal.com/favicon.ico",
      phishing: { credentialHarvest: true, externalFormPost: true },
    });
    const scan2 = analyzeClone({
      pageOrigin: "https://github.com",
      ...REALISTIC_ASSETS,
    });
    const scan3 = analyzeClone({ pageOrigin: "" });
    expect(scan2.confidence).toBe(0);
    expect(scan2.reasons).toEqual([]);
    expect(scan3.confidence).toBe(0);
    expect(scan1.confidence).toBeGreaterThan(0);
  });

  it("handles malformed origin without throwing", () => {
    expect(() => analyzeClone({ pageOrigin: "not-a-url" })).not.toThrow();
    expect(() => analyzeClone({})).not.toThrow();
    expect(() => analyzeClone(null)).not.toThrow();
  });

  it("ignores empty/undefined hosts in comparison", () => {
    const r = analyzeClone({
      pageOrigin: "https://example.com",
      scripts: ["", "javascript:void(0)", "data:text/js,foo"],
      styles: [], images: [""],
      favicon: "",
    });
    expect(r.confidence).toBe(0);
  });
});
