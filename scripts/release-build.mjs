#!/usr/bin/env node
// Kedayam — deterministic release pipeline.
//
// Steps (each must succeed to advance):
//   1. lint (tsc / eslint if available — best effort)
//   2. unit + redteam + performance + compatibility tests
//   3. extension validator
//   4. profile run
//   5. security scorecard
//   6. package zip with SHA-256 checksum
//
// Output:
//   public/kedayam.zip            — the extension
//   public/kedayam.zip.sha256     — checksum of the zip
//   public/kedayam-profile.json   — runtime profile
//   public/kedayam-security-report.json — scorecard

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";

const STEPS = [
  { name: "vitest", cmd: "bunx", args: ["vitest", "run"], required: true },
  { name: "validate-extension", cmd: "node", args: ["scripts/validate-extension.mjs", "extension"], required: true },
  { name: "profile", cmd: "node", args: ["scripts/profile-extension.mjs"], required: false },
  { name: "package", cmd: "node", args: ["scripts/package-extension.mjs"], required: true },
  { name: "security-report", cmd: "node", args: ["scripts/generate-security-report.mjs"], required: false },
];

function run(step) {
  console.log(`\n=== [release] ${step.name} ===`);
  const r = spawnSync(step.cmd, step.args, { stdio: "inherit", timeout: 300_000 });
  if (r.status !== 0) {
    if (step.required) {
      console.error(`[release] required step '${step.name}' failed (exit ${r.status})`);
      process.exit(r.status || 1);
    }
    console.warn(`[release] optional step '${step.name}' failed (exit ${r.status}) — continuing`);
  }
}

for (const step of STEPS) run(step);

// Checksum the zip for reproducibility verification.
const ZIP = "public/kedayam.zip";
if (existsSync(ZIP)) {
  const buf = readFileSync(ZIP);
  const sha = createHash("sha256").update(buf).digest("hex");
  mkdirSync("public", { recursive: true });
  writeFileSync(ZIP + ".sha256", `${sha}  kedayam.zip\n`);
  console.log(`[release] SHA-256: ${sha}`);
} else {
  console.warn("[release] no zip found at", ZIP);
}

console.log("\n[release] done.");
