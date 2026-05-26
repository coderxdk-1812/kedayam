#!/usr/bin/env node
// Kedayam — extension profiler. Measures pipeline cost across a fixed
// corpus of representative URLs and writes a JSON report. Runs entirely
// locally; no network, no telemetry.
//
// Usage:  node scripts/profile-extension.mjs [--out path]

import { performance } from "node:perf_hooks";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { evaluateUrl } from "../extension/lib/trustEngine.js";
import { analyzeSensitivePayload } from "../extension/lib/sensitiveDataEngine.js";

const OUT = process.argv.includes("--out")
  ? process.argv[process.argv.indexOf("--out") + 1]
  : "public/kedayam-profile.json";

const URLS = [
  "https://google.com", "https://microsoft.com", "https://github.com",
  "https://accounts.google.com", "https://login.microsoftonline.com",
  "https://paypal.com", "https://wikipedia.org", "https://m1cros0ft.example/login",
  "https://paypa1.example/login", "https://verify-now.example.cc",
  "https://docs.google.com/document/d/abc", "https://app.slack.com/client",
  "https://notion.so/page", "https://www.figma.com/files",
  "https://discord.com/channels/@me", "https://stripe.com/docs",
];

const SAMPLES = [
  "alice@example.com 555-123-4567",
  "AKIAIOSFODNN7EXAMPLE",
  "ghp_realLookingValue1234abcd5678efgh9012ijkl3456",
  "-----BEGIN RSA PRIVATE KEY-----",
  "lorem ipsum ".repeat(500),
];

async function run() {
  const evalTimes = [];
  for (const u of URLS) {
    const t = performance.now();
    await evaluateUrl(u, { settings: { detection: { sensitivity: "balanced" } } });
    evalTimes.push(performance.now() - t);
  }
  const scanTimes = [];
  for (const s of SAMPLES) {
    const t = performance.now();
    analyzeSensitivePayload(s);
    scanTimes.push(performance.now() - t);
  }
  const summary = (arr) => ({
    min: round(Math.min(...arr)), max: round(Math.max(...arr)),
    mean: round(arr.reduce((a, b) => a + b, 0) / arr.length),
    p95: round(percentile(arr, 95)),
  });
  const report = {
    generatedAt: new Date().toISOString(),
    evaluateUrl: { count: URLS.length, ms: summary(evalTimes) },
    sensitiveScan: { count: SAMPLES.length, ms: summary(scanTimes) },
    node: process.version,
  };
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(report, null, 2));
  console.log("[profile] wrote", OUT);
  console.log(JSON.stringify(report, null, 2));
}

function round(n) { return Math.round(n * 100) / 100; }
function percentile(arr, p) {
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

run().catch((e) => { console.error(e); process.exit(1); });
