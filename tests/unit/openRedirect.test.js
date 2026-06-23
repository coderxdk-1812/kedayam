import { describe, it, expect } from "vitest";
import { analyzeOpenRedirect } from "../../extension/lib/openRedirect.js";

describe("analyzeOpenRedirect", () => {
  it("flags an external redirect parameter", () => {
    const r = analyzeOpenRedirect("https://trusted.com/out?url=https://evil.tld/login");
    expect(r.external).toBe(true);
    expect(r.targetHost).toBe("evil.tld");
    expect(r.signals[0].id).toBe("open-redirect");
  });

  it("escalates a URL-encoded (hidden) destination", () => {
    const r = analyzeOpenRedirect("https://t.com/r?redirect=https%3A%2F%2Fevil.tld%2Fx");
    expect(r.external).toBe(true);
    expect(r.signals[0].severity).toBe("high");
  });

  it("escalates a raw-IP destination", () => {
    const r = analyzeOpenRedirect("https://t.com/go?next=http://203.0.113.9/x");
    expect(r.external).toBe(true);
    expect(r.signals[0].severity).toBe("high");
  });

  it("ignores same-site redirects", () => {
    const r = analyzeOpenRedirect("https://trusted.com/login?next=https://trusted.com/home");
    expect(r.external).toBe(false);
    expect(r.signals.length).toBe(0);
  });

  it("ignores relative-path redirect values", () => {
    const r = analyzeOpenRedirect("https://trusted.com/login?next=/dashboard");
    expect(r.external).toBe(false);
  });

  it("ignores URLs with no redirect parameter", () => {
    expect(analyzeOpenRedirect("https://trusted.com/search?q=hello").external).toBe(false);
  });

  it("handles protocol-relative destinations", () => {
    const r = analyzeOpenRedirect("https://t.com/out?u=//evil.tld/x");
    expect(r.external).toBe(true);
    expect(r.targetHost).toBe("evil.tld");
  });

  it("is safe on malformed input", () => {
    expect(analyzeOpenRedirect("not a url").external).toBe(false);
  });
});
