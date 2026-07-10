#!/usr/bin/env node
// Kedayam — committed-artifact verifier (platform-independent).
//
// Proves the committed public/kedayam.zip is NOT stale: its CONTENTS must match
// the current extension/ source exactly. We compare extracted file contents, not
// zip bytes, because the `zip` CLI is not byte-identical across macOS and Linux
// (different Info-ZIP/deflate builds) — so a byte-for-byte rebuild comparison
// would false-fail in CI. Content equality is the guarantee that actually
// matters for "does the shipped package reflect the code?".
//
// Also checks the sha256 sidecar matches the committed zip bytes.
//
// Exit non-zero on any drift.

import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, relative, sep } from "node:path";
import { tmpdir } from "node:os";

const ZIP = "public/kedayam.zip";
const SRC = "extension";
const fail = (msg) => {
  console.error(`::error::[verify-artifact] ${msg}`);
  process.exit(1);
};

// 1. sha256 sidecar integrity.
const zipBuf = readFileSync(ZIP);
const sha = createHash("sha256").update(zipBuf).digest("hex");
const sidecar = readFileSync(`${ZIP}.sha256`, "utf8").trim().split(/\s+/)[0];
if (sha !== sidecar)
  fail(`sha256 sidecar (${sidecar.slice(0, 12)}…) != actual zip (${sha.slice(0, 12)}…)`);

// 2. Extract and compare contents against the source tree.
const out = mkdtempSync(join(tmpdir(), "kedayam-verify-"));
const unzip = spawnSync("unzip", ["-oq", ZIP, "-d", out], { stdio: "inherit" });
if (unzip.status !== 0) fail("could not unzip the committed artifact");

// List every file under `base` as sorted, forward-slash relative paths.
const rel = (base) => {
  const acc = [];
  const rec = (d) => {
    for (const name of readdirSync(d)) {
      if (name === ".DS_Store") continue;
      const abs = join(d, name);
      if (statSync(abs).isDirectory()) rec(abs);
      else acc.push(relative(base, abs).split(sep).join("/"));
    }
  };
  rec(base);
  return acc.sort();
};

const srcFiles = rel(SRC);
const zipFiles = rel(out);

const missing = srcFiles.filter((f) => !zipFiles.includes(f));
const extra = zipFiles.filter((f) => !srcFiles.includes(f));
if (missing.length) fail(`source files missing from the zip: ${missing.join(", ")}`);
if (extra.length) fail(`zip has files not in source: ${extra.join(", ")}`);

const differ = srcFiles.filter(
  (f) => !readFileSync(join(SRC, f)).equals(readFileSync(join(out, f))),
);
rmSync(out, { recursive: true, force: true });
if (differ.length) {
  fail(
    `the committed zip is STALE — these files differ from source: ${differ.join(", ")}. ` +
      `Run: node scripts/release-build.mjs && node scripts/release-certify.mjs && commit.`,
  );
}

console.log(`[verify-artifact] OK — ${srcFiles.length} files match source; sha256 sidecar valid.`);
