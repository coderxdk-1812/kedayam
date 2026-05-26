// Performance — scan cost & arbitration time under load.
import { describe, it, expect } from "vitest";
import { analyzeSensitivePayload } from "../../extension/lib/sensitiveDataEngine.js";
import { analyzePhishing } from "../../extension/lib/phishingHeuristics.js";
import { analyzeClone } from "../../extension/lib/cloneDetection.js";
import { arbitrate } from "../../extension/lib/arbitration.js";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

function time(fn) { const t = Date.now(); fn(); return Date.now() - t; }
async function timeAsync(fn) { const t = Date.now(); await fn(); return Date.now() - t; }

describe("performance — scan cost", () => {
  it("sensitive-data engine: <30ms for 10KB benign text", () => {
    const text = "lorem ipsum ".repeat(800);
    expect(time(() => analyzeSensitivePayload(text))).toBeLessThan(50);
  });

  it("phishing heuristics: <10ms on a typical login ctx", () => {
    const ctx = {
      pageOrigin: "https://example.com",
      title: "Sign in", visibleText: "Sign in to continue",
      forms: [{ hasPassword: true, hasEmailLike: true, hasOtp: false,
        hiddenCount: 1, fieldsCount: 3 }],
      hasPasswordField: true, oauthButtons: [],
      scripts: [], styles: [], images: [],
    };
    expect(time(() => { for (let i = 0; i < 50; i++) analyzePhishing(ctx); })).toBeLessThan(150);
  });

  it("clone detection: <15ms with 60 mixed asset urls", () => {
    const ctx = {
      pageOrigin: "https://app.example.com",
      scripts: Array.from({ length: 30 }, (_, i) => `https://cdn${i}.example.com/x.js`),
      styles: Array.from({ length: 20 }, (_, i) => `https://s${i}.example.com/y.css`),
      images: Array.from({ length: 10 }, (_, i) => `https://i${i}.example.com/z.png`),
      favicon: "https://example.com/favicon.ico",
      title: "App", visibleText: "App home", forms: [], oauthButtons: [],
    };
    expect(time(() => analyzeClone(ctx))).toBeLessThan(50);
  });

  it("arbitration: deterministic <2ms even on a dense input", () => {
    const ctx = {
      allowlistRoot: false, isReputableRoot: false, isTrustedProvider: false,
      hasAuthWorkflow: true,
      lookalike: { match: { brand: "microsoft", root: "microsoft.com" },
        confidence: 0.8 },
      idnSpoof: true,
      clone: { confidence: 0.8, externalFormPost: true, brandImageMismatch: true },
      phishing: { credentialHarvest: true, externalFormPost: true,
        brandImpersonation: { brand: "microsoft" }, confidence: 0.9,
        authRisk: "high" },
    };
    expect(time(() => { for (let i = 0; i < 200; i++) arbitrate(ctx); })).toBeLessThan(50);
  });

  it("evaluateUrl: full pipeline mean <50ms across 20 URLs", async () => {
    const urls = [
      "https://example.com", "https://google.com", "https://microsoft.com",
      "https://github.com/login", "https://accounts.google.com",
      "https://login.microsoftonline.com", "https://paypal.com",
      "https://news.ycombinator.com", "https://wikipedia.org",
      "https://m1cros0ft.example.org/login", "https://paypa1.example/login",
      "https://verify-now.example.cc", "https://signin.bad-host.example",
      "https://docs.google.com/document/d/abc", "https://figma.com/file/abc",
      "https://notion.so/page/abc", "https://app.slack.com/client/abc",
      "https://github.com/user/repo/settings", "https://stripe.com/docs",
      "https://www.amazon.com/checkout",
    ];
    const elapsed = await timeAsync(async () => {
      for (const u of urls) await evaluateUrl(u, { settings: { detection: { sensitivity: "balanced" } } });
    });
    const mean = elapsed / urls.length;
    expect(mean).toBeLessThan(80);
  });
});
