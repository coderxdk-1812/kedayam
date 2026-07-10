import { test, expect, chromium } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXT_PATH = path.resolve(__dirname, "../../extension");

// MV3 extensions (with a background service worker) only load in the full
// Chromium build's new headless mode — not the default "headless shell". The
// `channel: "chromium"` selects that build so --load-extension works in CI.
function launchWithExtension() {
  return chromium.launchPersistentContext("", {
    channel: "chromium",
    headless: true,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      "--no-sandbox",
    ],
  });
}

async function waitForWorker(ctx: Awaited<ReturnType<typeof launchWithExtension>>) {
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 15_000 });
  return sw;
}

test("loads the unpacked extension and registers a service worker", async () => {
  const ctx = await launchWithExtension();
  try {
    const sw = await waitForWorker(ctx);
    expect(sw.url()).toContain("background.js");

    // Smoke-check the extension runtime is live and correctly configured.
    // (Trust-engine scoring is covered exhaustively by the unit suite; dynamic
    // import() is disallowed inside a running service worker, so we don't call
    // evaluateUrl here.)
    const info = await sw.evaluate(() => ({
      version: chrome.runtime.getManifest().version,
      name: chrome.runtime.getManifest().name,
      id: chrome.runtime.id,
    }));
    expect(info.name).toBe("Kedayam Browser Shield");
    expect(info.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(info.id).toBeTruthy();
  } finally {
    await ctx.close();
  }
});

test("popup HTML renders without errors", async () => {
  const ctx = await launchWithExtension();
  try {
    const sw = await waitForWorker(ctx);
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

test("ad/tracker DNR ruleset ships enabled", async () => {
  const ctx = await launchWithExtension();
  try {
    const sw = await waitForWorker(ctx);
    const enabled = await sw.evaluate(async () => {
      return chrome.declarativeNetRequest.getEnabledRulesets();
    });
    expect(enabled).toContain("kedayam_adblock");
  } finally {
    await ctx.close();
  }
});

test("options Transparency panel renders the protection catalog", async () => {
  const ctx = await launchWithExtension();
  try {
    const sw = await waitForWorker(ctx);
    const extensionId = sw.url().split("/")[2];
    const page = await ctx.newPage();
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(String(e)));
    await page.goto(`chrome-extension://${extensionId}/options/options.html`);

    // Wait for the catalog (imported module + settings message + render) to populate.
    await expect(page.locator("#protection-overview .protection-item").first()).toBeVisible();
    const count = await page.locator("#protection-overview .protection-item").count();
    expect(count).toBeGreaterThanOrEqual(8);

    // Flagship layers + honest ratings/limits are surfaced to the user.
    await expect(page.locator(".pi-title", { hasText: "ClickFix" })).toBeVisible();
    await expect(page.locator(".uplift.u-HIGH").first()).toBeVisible();
    await expect(page.locator("#protection-limits li").first()).toBeVisible();
    await expect(page.locator("#protection-summary")).toContainText("layers active");
    expect(errors).toEqual([]);
  } finally {
    await ctx.close();
  }
});
