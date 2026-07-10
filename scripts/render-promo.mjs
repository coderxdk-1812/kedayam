#!/usr/bin/env node
// Renders public/kedayam-promo.html to a shareable PNG (2× = 2160×2700).
// Run: bun run promo:image
import { chromium } from "@playwright/test";
import { pathToFileURL } from "node:url";
import path from "node:path";

const html = path.resolve("public/kedayam-promo.html");
const out = path.resolve("public/kedayam-promo.png");
const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: 1080, height: 1350 },
  deviceScaleFactor: 2,
});
await page.goto(pathToFileURL(html).href, { waitUntil: "networkidle" });
await page.waitForTimeout(600); // let webfonts settle
await page.screenshot({ path: out, clip: { x: 0, y: 0, width: 1080, height: 1350 } });
await browser.close();
console.log(`[promo] wrote ${out}`);
