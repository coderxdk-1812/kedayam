#!/usr/bin/env node
// Kedayam — cross-browser packager (Chrome / Edge / Firefox).
//
// Emits per-store zips, all byte-deterministic (fixed mtimes + sorted + -X),
// like scripts/package-extension.mjs. Kept SEPARATE from that script so the
// CI-gated Chrome artifact pipeline is never disturbed.
//
//   * Chrome  → public/kedayam-chrome.zip   (identical to kedayam.zip)
//   * Edge    → public/kedayam-edge.zip      (Edge accepts the same MV3 package)
//   * Firefox → public/kedayam-firefox.zip   (Gecko-adapted manifest, see below)
//
// The Firefox package swaps in a Gecko-adapted manifest (background event-page,
// browser_specific_settings, Chrome-only keys stripped). It is structurally
// valid but STILL NEEDS a Firefox runtime pass (web-ext lint / load) before it
// ships — flagged in STATUS.md.

import { createHash } from "node:crypto";
import {
  mkdirSync,
  rmSync,
  cpSync,
  readdirSync,
  statSync,
  utimesSync,
  writeFileSync,
  readFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { join, relative, sep } from "node:path";
import { tmpdir } from "node:os";
import { toFirefoxManifest } from "./lib/firefoxManifest.mjs";

const SRC = "extension";
const FIXED = new Date("1980-01-01T00:00:00Z");
mkdirSync("public", { recursive: true });

function deterministicZip(stageDir, absZip) {
  const walk = (dir) => {
    const out = [];
    for (const name of readdirSync(dir)) {
      const abs = join(dir, name);
      if (statSync(abs).isDirectory()) out.push(...walk(abs));
      else if (name !== ".DS_Store") out.push(abs);
    }
    return out;
  };
  const files = walk(stageDir)
    .map((abs) => relative(stageDir, abs).split(sep).join("/"))
    .sort();
  for (const rel of files) utimesSync(join(stageDir, rel), FIXED, FIXED);
  rmSync(absZip, { force: true });
  const zipper = spawnSync("zip", ["-X", "-q", absZip, "-@"], {
    cwd: stageDir,
    input: files.join("\n") + "\n",
    stdio: ["pipe", "inherit", "inherit"],
  });
  if (zipper.status !== 0) process.exit(zipper.status ?? 1);
  return files.length;
}

function build(target, transformManifest) {
  const stage = join(tmpdir(), `kedayam-${target}`);
  rmSync(stage, { recursive: true, force: true });
  cpSync(SRC, stage, { recursive: true });
  if (transformManifest) {
    const manifest = JSON.parse(readFileSync(join(stage, "manifest.json"), "utf8"));
    writeFileSync(
      join(stage, "manifest.json"),
      JSON.stringify(transformManifest(manifest), null, 2) + "\n",
    );
  }
  const absZip = join(process.cwd(), "public", `kedayam-${target}.zip`);
  const count = deterministicZip(stage, absZip);
  rmSync(stage, { recursive: true, force: true });
  // The per-store zips are committed, so each ships a sha256 sidecar in the
  // same shape as kedayam.zip.sha256 — reviewers can verify the exact upload.
  const sha = createHash("sha256").update(readFileSync(absZip)).digest("hex");
  writeFileSync(`${absZip}.sha256`, `${sha}  kedayam-${target}.zip\n`);
  console.log(
    `[crossbrowser] ${target}: public/kedayam-${target}.zip (${count} files) ${sha.slice(0, 12)}…`,
  );
}

// Validate the extension once up front (reuses the Chrome validator).
const v = spawnSync("bun", ["scripts/validate-extension.mjs", SRC], { stdio: "inherit" });
if (v.status !== 0) process.exit(v.status ?? 1);

build("chrome", null);
build("edge", null); // Edge runs Chromium MV3 unmodified
build("firefox", (m) => toFirefoxManifest(m));

console.log("[crossbrowser] done. NOTE: run web-ext lint on the Firefox zip before submitting.");
