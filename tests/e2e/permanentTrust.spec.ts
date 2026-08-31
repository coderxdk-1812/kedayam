// End-to-end proof for "Always trust this site" + the VirusTotal link.
//
// Loads the real unpacked extension, serves a phishing fixture from a
// lookalike origin (fulfilled locally — no network), waits for the warning
// modal the content script renders, then drives both new controls and
// asserts the persisted effect in chrome.storage.
import { test, expect, chromium, type BrowserContext } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXT_PATH = path.resolve(__dirname, "../../extension");
const FIXTURE = fs.readFileSync(
  path.resolve(__dirname, "../fixtures/phishing/fake-bank.html"),
  "utf8",
);
const PHISH_URL = "https://secure-signon.chase-verify-login.tk/signon";

function launchWithExtension() {
  return chromium.launchPersistentContext("", {
    channel: "chromium",
    headless: true,
    args: [
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`,
      "--no-sandbox",
      "--ignore-certificate-errors",
    ],
  });
}

async function waitForWorker(ctx: BrowserContext) {
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 15_000 });
  return sw;
}

// Serve every request locally so the test never touches the network.
async function stubNetwork(ctx: BrowserContext) {
  await ctx.route("**/*", (route) =>
    route.fulfill({ status: 200, contentType: "text/html", body: FIXTURE }),
  );
}

test("warning modal offers permanent trust and a VirusTotal link", async () => {
  const ctx = await launchWithExtension();
  try {
    const sw = await waitForWorker(ctx);
    await stubNetwork(ctx);
    const page = await ctx.newPage();
    await page.goto(PHISH_URL);

    const modal = page.locator("#kedayam-root .ked-modal");
    await expect(modal).toBeVisible({ timeout: 20_000 });

    // The VirusTotal call to action carries the ORIGIN only — never the path,
    // and renders full-width above the decision buttons.
    const vt = modal.locator(".ked-verify-btn");
    await expect(vt).toBeVisible();
    const [vtBox, modalBox] = [await vt.boundingBox(), await modal.boundingBox()];
    expect(vtBox!.width).toBeGreaterThan(modalBox!.width * 0.85);
    expect(await vt.getAttribute("href")).toBe(
      "https://www.virustotal.com/gui/search?query=" +
        encodeURIComponent("https://secure-signon.chase-verify-login.tk/"),
    );
    expect(await vt.getAttribute("rel")).toContain("noopener");

    // First click only arms the button — a mis-click can't silence the scanner.
    // Session-only trust is gone from the verdict modal — Always trust replaces it.
    await expect(modal.locator("button[data-act='trust']")).toHaveCount(0);

    const always = modal.locator("button[data-act='always-trust']");
    await expect(always).toHaveText("Always trust this site");
    await always.click();
    await expect(always).toHaveText("Click again to confirm");
    await expect(modal).toBeVisible();

    // Second click commits: the modal closes and the root lands in the allowlist.
    await always.click();
    await expect(modal).toBeHidden();

    await expect
      .poll(
        async () =>
          await sw.evaluate(async () => {
            const { "kedayam:v1:settings": s } =
              await chrome.storage.local.get("kedayam:v1:settings");
            return s?.allowlist ?? [];
          }),
        { timeout: 10_000 },
      )
      .toContain("chase-verify-login.tk");

    // ...and the page no longer gets flagged after a reload.
    await page.reload();
    await page.waitForTimeout(3000);
    await expect(page.locator("#kedayam-root .ked-modal")).toHaveCount(0);
  } finally {
    await ctx.close();
  }
});

test("popup exposes Always trust and the VirusTotal link", async () => {
  const ctx = await launchWithExtension();
  try {
    const sw = await waitForWorker(ctx);
    const extensionId = sw.url().split("/")[2];
    await stubNetwork(ctx);
    const page = await ctx.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup/popup.html`);
    await expect(page.locator("#always-trust")).toHaveText("Always trust");
    await expect(page.locator("#vt-link")).toHaveCount(1);
    await expect(page.locator("#trust")).toHaveCount(0);
  } finally {
    await ctx.close();
  }
});
