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
  });
  it("flags favicon hosted on an unrelated domain", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker-site.tld",
      scripts: [], styles: [], images: [],
      favicon: "https://paypal.com/favicon.ico",
    });
    expect(r.faviconMismatch).toBe(true);
    expect(r.confidence).toBeGreaterThanOrEqual(0.5);
  });
  it("flags brand image theft", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker-site.tld",
      scripts: [], styles: [],
      images: ["https://paypal.com/assets/logo.png"],
    });
    expect(r.brandImageMismatch).toBe(true);
    expect(r.reasons.some((x) => x.includes("paypal"))).toBe(true);
  });
  it("flags a high cross-origin asset ratio", () => {
    const r = analyzeClone({
      pageOrigin: "https://attacker.tld",
      scripts: [
        "https://evil1.tld/a.js", "https://evil2.tld/b.js",
        "https://evil3.tld/c.js", "https://evil4.tld/d.js",
      ],
      styles: [], images: [],
    });
    expect(r.crossOriginRatio).toBeGreaterThan(0.5);
    expect(r.confidence).toBeGreaterThan(0);
  });
});