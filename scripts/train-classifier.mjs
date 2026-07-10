#!/usr/bin/env node
// Kedayam — phishing-classifier trainer & benchmark (Tier-1 roadmap).
//
// Fits the classifier's weights on a REAL labeled corpus and MEASURES precision /
// recall / false-positive rate, replacing the hand-tuned placeholder. Emits:
//   * extension/lib/rules/classifierWeights.js  — fitted weights (shipped)
//   * public/kedayam-classifier-eval.json         — measured metrics (evidence)
//
// Corpus (host-level, URL-shape only — no live DOM):
//   * phishing  = FREE feeds (Phishing Army + OpenPhish + URLhaus)
//   * benign    = top-visited domains (zer0h/top-1m mirror)
//
// HONEST SCOPE: the corpus has no page DOM, so we fit only the host-shape
// features that actually vary here (punycode, abused TLD, subdomain depth, digit
// ratio, hyphens, lure tokens, brand-in-subdomain). The transport/DOM features
// (notHttps, password field, off-origin form, external scripts, obfuscation) keep
// fixed EXPERT PRIORS — they are strong runtime signals but are constant/absent in
// a URL-only corpus, so training can't learn them. This is stated in the metrics.
//
// Deliberate, committed step (feeds change over time): `bun run train:classifier`.
// Deterministic given a fixed corpus (seeded shuffle, batch gradient descent).

import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { FREE_FEEDS, parseFeed } from "../extension/lib/threatFeed.js";
import { extractFeatures } from "../extension/lib/phishingClassifier.js";
import { rootDomain } from "../extension/lib/lookalike.js";
import { isSafelistedRoot } from "../extension/lib/safelist.js";
import { KNOWN_REPUTABLE_ROOTS, TRUSTED_LOGIN_PROVIDERS } from "../extension/lib/trustEngine.js";

const PER_CLASS = Number(process.env.KEDAYAM_TRAIN_N || 6000);
const BENIGN_URL =
  "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-100000-domains";
const WEIGHTS_OUT = "extension/lib/rules/classifierWeights.js";
const EVAL_OUT = "public/kedayam-classifier-eval.json";

// Features fitted from the corpus (they vary across host shapes).
const TRAINABLE = [
  "punycode",
  "abusedTld",
  "manySubdomains",
  "hostDigitsRatio",
  "hostHyphens",
  "lureTokens",
  "brandInSubdomain",
];
// Fixed expert priors for runtime-only features (constant/absent in a URL corpus).
const FIXED_PRIORS = Object.freeze({
  notHttps: 1.1,
  hasPasswordField: 1.0,
  crossOriginForm: 1.7,
  manyExternalScripts: 0.7,
  obfuscation: 1.2,
});

// --- deterministic PRNG (mulberry32) so splits are reproducible ---
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function shuffle(arr, rand) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

async function fetchText(url) {
  const res = await fetch(url, {
    headers: { "user-agent": "kedayam-train/1.0" },
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.text();
}

function normHost(h) {
  return String(h)
    .trim()
    .toLowerCase()
    .replace(/^www\./, "");
}
function isBenignSafe(h) {
  const r = rootDomain(h);
  return (
    KNOWN_REPUTABLE_ROOTS.has(h) ||
    KNOWN_REPUTABLE_ROOTS.has(r) ||
    TRUSTED_LOGIN_PROVIDERS.has(h) ||
    TRUSTED_LOGIN_PROVIDERS.has(r) ||
    isSafelistedRoot(h) ||
    isSafelistedRoot(r)
  );
}

// --- gather corpus ---
console.log("[train] fetching phishing feeds…");
const phishSet = new Set();
for (const feed of FREE_FEEDS) {
  try {
    const set = parseFeed(await fetchText(feed.url));
    for (const h of set) phishSet.add(normHost(h));
    console.log(`[train]   ${feed.id}: ${set.size}`);
  } catch (e) {
    console.warn(`[train]   ${feed.id}: ${e.message} — skipped`);
  }
}

console.log("[train] fetching benign top-sites…");
const benignAll = (await fetchText(BENIGN_URL))
  .split(/\r?\n/)
  .map(normHost)
  .filter((h) => h && h.includes(".") && !/\s/.test(h));

// Dedupe across classes; drop safelisted from phishing to avoid label noise.
const benignSet = new Set();
for (const h of benignAll) {
  if (benignSet.size >= PER_CLASS) break;
  if (phishSet.has(h)) continue;
  benignSet.add(h);
}
const phishing = [...phishSet]
  .filter((h) => !benignSet.has(h) && !isBenignSafe(h))
  .slice(0, PER_CLASS);
const benign = [...benignSet].slice(0, phishing.length); // balance classes
if (phishing.length < 500 || benign.length < 500) {
  console.error(`[train] corpus too small (phishing=${phishing.length}, benign=${benign.length}).`);
  process.exit(1);
}
console.log(`[train] corpus: ${phishing.length} phishing + ${benign.length} benign`);

// --- featurize (host-level; label 1 = phishing) ---
const toVec = (host) => {
  const f = extractFeatures(`https://${host}/`);
  return TRAINABLE.map((k) => f[k] || 0);
};
const data = [
  ...phishing.map((h) => ({ x: toVec(h), y: 1 })),
  ...benign.map((h) => ({ x: toVec(h), y: 0 })),
];
shuffle(data, rng(1337));
const cut = Math.floor(data.length * 0.8);
const train = data.slice(0, cut);
const test = data.slice(cut);

// --- logistic regression via batch gradient descent (deterministic) ---
const sigmoid = (z) => 1 / (1 + Math.exp(-z));
const n = TRAINABLE.length;
let w = new Array(n).fill(0);
let b = 0;
const LR = 0.5;
const L2 = 0.001;
const EPOCHS = 4000;
for (let e = 0; e < EPOCHS; e++) {
  const gw = new Array(n).fill(0);
  let gb = 0;
  for (const { x, y } of train) {
    let z = b;
    for (let i = 0; i < n; i++) z += w[i] * x[i];
    const err = sigmoid(z) - y;
    for (let i = 0; i < n; i++) gw[i] += err * x[i];
    gb += err;
  }
  const m = train.length;
  for (let i = 0; i < n; i++) {
    w[i] -= LR * (gw[i] / m + L2 * w[i]);
    // Monotonicity prior: every trainable feature can only RAISE phishing risk
    // (more digits / deeper subdomains / a brand in a subdomain is never safer).
    // Projected gradient descent keeps the model interpretable and prevents the
    // fit from learning a counterintuitive negative weight on a rare feature.
    if (w[i] < 0) w[i] = 0;
  }
  b -= LR * (gb / m);
}
const round = (x, p = 4) => Math.round(x * 10 ** p) / 10 ** p;

// --- evaluate at the operating thresholds the runtime uses ---
function metricsAt(threshold) {
  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0;
  for (const { x, y } of test) {
    let z = b;
    for (let i = 0; i < n; i++) z += w[i] * x[i];
    const pred = sigmoid(z) >= threshold ? 1 : 0;
    if (pred === 1 && y === 1) tp++;
    else if (pred === 1 && y === 0) fp++;
    else if (pred === 0 && y === 0) tn++;
    else fn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const fpRate = fp + tn ? fp / (fp + tn) : 0;
  const accuracy = (tp + tn) / test.length;
  return {
    threshold,
    precision: round(precision),
    recall: round(recall),
    f1: round(f1),
    falsePositiveRate: round(fpRate),
    accuracy: round(accuracy),
    confusion: { tp, fp, tn, fn },
  };
}
// Runtime operating points (see phishingClassifier labels): the classifier only
// fires as CORROBORATING evidence, so we pick high-precision thresholds to keep
// the always-on false-positive rate low — a bare abused-TLD host (e.g. abc.xyz)
// must stay below "warn". warn = "suspicious" (0.80); block = "phishing" (0.92).
const atWarn = metricsAt(0.8);
const atStrict = metricsAt(0.92);
console.log("[train] metrics @0.80 (warn):", JSON.stringify(atWarn));
console.log("[train] metrics @0.92 (block):", JSON.stringify(atStrict));

// --- emit fitted weights (fitted host-shape + fixed runtime priors) ---
const fittedWeights = {};
TRAINABLE.forEach((k, i) => (fittedWeights[k] = round(w[i], 4)));
const WEIGHTS = { ...FIXED_PRIORS, ...fittedWeights };
const BIAS = round(b, 4);

const weightsBody = `// Kedayam — phishing-classifier weights (AUTO-GENERATED by bun run train:classifier).
//
// DO NOT edit by hand. Host-shape weights are FITTED on a labeled corpus
// (${phishing.length} phishing + ${benign.length} benign); the runtime-only features
// (${Object.keys(FIXED_PRIORS).join(", ")}) keep fixed expert priors because a
// URL-only corpus can't fit them. Measured metrics live in ${EVAL_OUT}.
export const BIAS = ${BIAS};
export const WEIGHTS = Object.freeze(${JSON.stringify(WEIGHTS, null, 2)});
export const CLASSIFIER_META = Object.freeze({
  corpus: { phishing: ${phishing.length}, benign: ${benign.length}, level: "host-url-shape" },
  fittedFeatures: ${JSON.stringify(TRAINABLE)},
  fixedPriorFeatures: ${JSON.stringify(Object.keys(FIXED_PRIORS))},
  metrics: { warn: ${JSON.stringify(atWarn)}, block: ${JSON.stringify(atStrict)} },
});
`;
writeFileSync(WEIGHTS_OUT, weightsBody);

const evalReport = {
  corpus: {
    phishing: phishing.length,
    benign: benign.length,
    level: "host-url-shape",
    split: "80/20",
  },
  note:
    "Host-URL-shape benchmark (no live DOM). Fitted features: " +
    TRAINABLE.join(", ") +
    ". Fixed runtime priors: " +
    Object.keys(FIXED_PRIORS).join(", ") +
    ".",
  warn: atWarn,
  block: atStrict,
};
writeFileSync(EVAL_OUT, JSON.stringify(evalReport, null, 2) + "\n");

// Format the generated weights module so it passes the project's lint gate on
// regeneration (JSON.stringify emits quoted keys / compact objects prettier rejects).
spawnSync("bunx", ["prettier", "--write", WEIGHTS_OUT], { stdio: "inherit" });
console.log(`[train] wrote ${WEIGHTS_OUT} and ${EVAL_OUT}`);
