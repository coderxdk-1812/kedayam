import { test, expect, chromium } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXT_PATH = path.resolve(__dirname, "../../extension");

test("loads the unpacked extension and registers a service worker", async () => {
  const ctx = await chromium.launchPersistentContext("", {
    headless: true,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      "--no-sandbox",
    ],
  });
  try {
    let [sw] = ctx.serviceWorkers();
    if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 10_000 });
    expect(sw.url()).toContain("background.js");

    // Confirm the trust engine module is reachable from the worker context.
    const result = await sw.evaluate(async () => {
      const mod = await import(chrome.runtime.getURL("lib/trustEngine.js"));
      const r = await mod.evaluateUrl("https://example.com/", {
        settings: { detection: { sensitivity: "balanced" }, apiKeys: {}, allowlist: [] },
      });
      return { score: r.score, status: r.status, summary: r.summary };
    });
    expect(result.status).toBe("safe");
    expect(result.score).toBeGreaterThanOrEqual(90);
  } finally {
    await ctx.close();
  }
});

test("popup HTML renders without errors", async () => {
  const ctx = await chromium.launchPersistentContext("", {
    headless: true,
    args: [`--disable-extensions-except=${EXT_PATH}`, `--load-extension=${EXT_PATH}`, "--no-sandbox"],
  });
  try {
    let [sw] = ctx.serviceWorkers();
    if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 10_000 });
    const extensionId = sw.url().split("/")[2];
    const page = await ctx.newPage();
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(String(e)));
    await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await expect(page.locator(".brand-name")).toHaveText("Kedayam");
    expect(errors).toEqual([]);
  } finally {
    await ctx.close();
  }
});
