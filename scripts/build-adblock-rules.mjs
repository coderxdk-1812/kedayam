#!/usr/bin/env node
// Kedayam — ad/tracker blocklist ruleset generator (declarativeNetRequest).
//
// Pulls a FREE, well-maintained ad/tracker DOMAIN list (Peter Lowe's list — small
// and low-breakage) and bakes it into extension/rules/adblock-rules.json as a DNR
// static ruleset. Blocking is 100% local (Chrome enforces the rules); no browsing
// data ever leaves the device. Safelisted / reputable roots are never blocked.
//
// Deliberate, committed step (the list changes over time): `bun run adblock:rules`.

import { mkdirSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { domainsToDnrRules, normalizeDomain } from "./lib/adblockRules.mjs";
import { rootDomain } from "../extension/lib/lookalike.js";
import { isSafelistedRoot } from "../extension/lib/safelist.js";
import { KNOWN_REPUTABLE_ROOTS, TRUSTED_LOGIN_PROVIDERS } from "../extension/lib/trustEngine.js";

const SOURCE =
  "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext";
const MAX = Number(process.env.KEDAYAM_ADBLOCK_MAX || 6000);
const OUT_DIR = "extension/rules";
const OUT = `${OUT_DIR}/adblock-rules.json`;

function neverBlock(host) {
  const r = rootDomain(host);
  return (
    KNOWN_REPUTABLE_ROOTS.has(host) ||
    KNOWN_REPUTABLE_ROOTS.has(r) ||
    TRUSTED_LOGIN_PROVIDERS.has(host) ||
    TRUSTED_LOGIN_PROVIDERS.has(r) ||
    isSafelistedRoot(host) ||
    isSafelistedRoot(r)
  );
}

const res = await fetch(SOURCE, {
  headers: { "user-agent": "kedayam-build/1.0" },
  redirect: "follow",
});
if (!res.ok) {
  console.error(`[adblock] source HTTP ${res.status} — aborting (kept existing ruleset).`);
  process.exit(1);
}
const raw = await res.text();
const domains = [];
for (const line of raw.split(/\r?\n/)) {
  const d = normalizeDomain(line);
  if (d && !neverBlock(d)) domains.push(d);
  if (domains.length >= MAX) break;
}
if (domains.length < 500) {
  console.error(`[adblock] only ${domains.length} domains parsed — aborting.`);
  process.exit(1);
}

const rules = domainsToDnrRules(domains);
mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(OUT, JSON.stringify(rules, null, 2) + "\n");
spawnSync("bunx", ["prettier", "--write", OUT], { stdio: "inherit" });
console.log(`[adblock] wrote ${OUT} — ${domains.length} domains in ${rules.length} DNR rule(s).`);
