#!/usr/bin/env node
// Kedayam — DOM-augmented classifier trainer (raises recall beyond URL shape).
//
// The URL-only trainer (train-classifier.mjs) keeps the DOM features
// (password field, off-origin login form, external scripts, obfuscation) as
// FIXED expert priors because a URL-only corpus can't fit them. This script
// CRAWLS live pages, extracts those DOM features, and FITS them too.
//
// METHODOLOGICAL GUARD (important): benign homepages rarely have a password
// field while phishing pages almost always do, so a naive crawl would learn
// "password field = phishing" and false-positive on legitimate LOGIN pages. So
// the benign corpus deliberately includes real login pages, and we ADOPT the
// DOM-fitted model ONLY IF it beats the current model AND does not regress on a
// held-out set of benign login pages. Otherwise we keep the expert priors and
// report the negative result — never ship a regression.
//
// Live crawling is fragile (dead phishing hosts, bot walls), so yields vary. The
// script is honest about corpus sizes and refuses to adopt on thin data.

import { writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { FREE_FEEDS, parseFeed } from "../extension/lib/threatFeed.js";
import { extractFeatures } from "../extension/lib/phishingClassifier.js";
import {
  BIAS as CUR_BIAS,
  WEIGHTS as CUR_WEIGHTS,
} from "../extension/lib/rules/classifierWeights.js";

const MAX_PHISH = Number(process.env.KEDAYAM_DOM_PHISH || 320);
const MAX_BENIGN = Number(process.env.KEDAYAM_DOM_BENIGN || 260);
const CONCURRENCY = Number(process.env.KEDAYAM_DOM_CONC || 20);
const TIMEOUT_MS = 5000;
const BENIGN_URL =
  "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-100000-domains";
const WEIGHTS_OUT = "extension/lib/rules/classifierWeights.js";
const EVAL_OUT = "public/kedayam-classifier-eval.json";

const ALL_FEATURES = Object.keys(CUR_WEIGHTS);
// Real login pages that legitimately have a password field — the guard set.
const BENIGN_LOGINS = [
  "https://github.com/login",
  "https://stackoverflow.com/users/login",
  "https://www.reddit.com/login",
  "https://www.dropbox.com/login",
  "https://www.linkedin.com/login",
  "https://gitlab.com/users/sign_in",
  "https://bitbucket.org/account/signin/",
  "https://wordpress.com/log-in",
  "https://www.pinterest.com/login/",
  "https://id.atlassian.com/login",
  "https://www.twitch.tv/login",
  "https://discord.com/login",
  "https://www.figma.com/login",
  "https://app.slack.com/signin",
  "https://vimeo.com/log_in",
];

function rng(seed) {
  let a = seed >>> 0;
  return () => {
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

async function fetchHtml(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctl.signal,
      redirect: "follow",
      headers: { "user-agent": "Mozilla/5.0 (compatible; kedayam-train/1.0)" },
    });
    if (!res.ok) return null;
    const ct = res.headers.get("content-type") || "";
    if (!/text\/html|application\/xhtml/i.test(ct)) return null;
    const txt = await res.text();
    return txt.slice(0, 400_000);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// Coarse, dependency-free HTML → pageContext (matches what content.js extracts).
function parseDom(html, url) {
  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return "";
    }
  })();
  const hasPasswordField = /<input[^>]+type\s*=\s*["']?password/i.test(html);
  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m;
  while ((m = formRe.exec(html)) && forms.length < 12) {
    const attrs = m[1];
    const inner = m[2];
    const action = (attrs.match(/action\s*=\s*["']([^"']*)["']/i) || [])[1] || "";
    forms.push({
      action,
      hasPassword: /<input[^>]+type\s*=\s*["']?password/i.test(inner),
      hasEmailLike: /<input[^>]+(type\s*=\s*["']?email|name\s*=\s*["']?(email|user|login))/i.test(
        inner,
      ),
    });
  }
  const scripts = [];
  const scriptRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
  while ((m = scriptRe.exec(html)) && scripts.length < 60) scripts.push({ src: m[1] });
  const textSample = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .slice(0, 4000);
  return { pageOrigin: origin, hasPasswordField, forms, scripts, textSample };
}

async function pool(items, worker) {
  const out = [];
  let i = 0;
  const runners = Array.from({ length: Math.min(CONCURRENCY, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await worker(items[idx], idx);
    }
  });
  await Promise.all(runners);
  return out;
}

async function fetchText(url) {
  const res = await fetch(url, {
    headers: { "user-agent": "kedayam-train/1.0" },
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

// --- assemble candidate URLs ---
console.log("[dom] gathering phishing URLs…");
const phishUrls = [];
for (const feed of FREE_FEEDS) {
  try {
    const raw = await fetchText(feed.url);
    if (feed.kind === "url") {
      for (const line of raw.split(/\r?\n/)) {
        const s = line.trim();
        if (/^https?:\/\//i.test(s)) phishUrls.push(s);
      }
    } else {
      for (const h of parseFeed(raw)) phishUrls.push(`http://${h}/`);
    }
  } catch (e) {
    console.warn(`[dom] ${feed.id}: ${e.message}`);
  }
}
shuffle(phishUrls, rng(7));
const phishCandidates = phishUrls.slice(0, MAX_PHISH * 3); // over-fetch; many are dead

console.log("[dom] gathering benign URLs…");
const topHosts = (await fetchText(BENIGN_URL))
  .split(/\r?\n/)
  .map((h) => h.trim().toLowerCase())
  .filter((h) => h && h.includes("."));
const benignCandidates = [
  ...BENIGN_LOGINS,
  ...topHosts.slice(0, MAX_BENIGN * 2).map((h) => `https://${h}/`),
];

// --- crawl ---
async function crawl(urls, label) {
  const rows = [];
  await pool(urls, async (url) => {
    const html = await fetchHtml(url);
    if (!html || html.length < 200) return;
    const ctx = parseDom(html, url);
    const f = extractFeatures(url, ctx);
    rows.push({
      url,
      x: ALL_FEATURES.map((k) => f[k] || 0),
      label,
      isLogin: BENIGN_LOGINS.includes(url),
    });
  });
  return rows;
}
console.log(
  `[dom] crawling ${phishCandidates.length} phishing + ${benignCandidates.length} benign…`,
);
const phishRows = (await crawl(phishCandidates, 1)).slice(0, MAX_PHISH);
const benignRows = await crawl(benignCandidates, 0);
const benignLogins = benignRows.filter(
  (r) => r.isLogin && r.x[ALL_FEATURES.indexOf("hasPasswordField")] === 1,
);
const benignOther = benignRows.filter((r) => !r.isLogin).slice(0, MAX_BENIGN);
console.log(
  `[dom] usable: ${phishRows.length} phishing, ${benignOther.length} benign homepages, ${benignLogins.length} benign LOGIN pages`,
);
if (phishRows.length < 120 || benignOther.length < 120) {
  console.error(
    "[dom] corpus too thin to fit DOM weights reliably — keeping expert priors. (Negative result: rerun with more live data.)",
  );
  process.exit(2);
}

// --- train (monotonic non-negative logistic on ALL features) ---
const data = shuffle([...phishRows, ...benignOther], rng(99));
const cut = Math.floor(data.length * 0.8);
const train = data.slice(0, cut);
const test = data.slice(cut);
const sigmoid = (z) => 1 / (1 + Math.exp(-z));
const n = ALL_FEATURES.length;

function fit() {
  let w = new Array(n).fill(0);
  let b = 0;
  const LR = 0.5,
    L2 = 0.001,
    EPOCHS = 4000;
  for (let e = 0; e < EPOCHS; e++) {
    const gw = new Array(n).fill(0);
    let gb = 0;
    for (const { x, label } of train) {
      let z = b;
      for (let i = 0; i < n; i++) z += w[i] * x[i];
      const err = sigmoid(z) - label;
      for (let i = 0; i < n; i++) gw[i] += err * x[i];
      gb += err;
    }
    const m = train.length;
    for (let i = 0; i < n; i++) {
      w[i] -= LR * (gw[i] / m + L2 * w[i]);
      if (w[i] < 0) w[i] = 0; // monotonic prior
    }
    b -= LR * (gb / m);
  }
  return { w, b };
}
const { w, b } = fit();
const round = (x, p = 4) => Math.round(x * 10 ** p) / 10 ** p;

function scoreWith(bias, weightsArr, x) {
  let z = bias;
  for (let i = 0; i < n; i++) z += weightsArr[i] * x[i];
  return sigmoid(z);
}
const curArr = ALL_FEATURES.map((k) => CUR_WEIGHTS[k] || 0);
function evalModel(bias, weightsArr, set, thr) {
  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0;
  for (const { x, label } of set) {
    const pred = scoreWith(bias, weightsArr, x) >= thr ? 1 : 0;
    if (pred && label) tp++;
    else if (pred && !label) fp++;
    else if (!pred && !label) tn++;
    else fn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  return { precision: round(precision), recall: round(recall), tp, fp, tn, fn };
}
const THR = 0.8;
const domMetrics = evalModel(b, w, test, THR);
const curMetrics = evalModel(CUR_BIAS, curArr, test, THR);
const loginFpDom = benignLogins.filter((r) => scoreWith(b, w, r.x) >= THR).length;
const loginFpCur = benignLogins.filter((r) => scoreWith(CUR_BIAS, curArr, r.x) >= THR).length;
console.log(
  "[dom] DOM-fitted @0.8:",
  JSON.stringify(domMetrics),
  "loginFP:",
  loginFpDom,
  "/",
  benignLogins.length,
);
console.log(
  "[dom] current    @0.8:",
  JSON.stringify(curMetrics),
  "loginFP:",
  loginFpCur,
  "/",
  benignLogins.length,
);

// --- adopt-or-keep decision ---
const recallBetter = domMetrics.recall > curMetrics.recall + 0.02;
const precisionOk = domMetrics.precision >= curMetrics.precision - 0.02;
const loginOk = loginFpDom <= loginFpCur; // must not regress on benign logins
const adopt = recallBetter && precisionOk && loginOk;

if (!adopt) {
  console.error(
    `[dom] NOT adopting DOM-fitted weights (recallBetter=${recallBetter}, precisionOk=${precisionOk}, loginOk=${loginOk}). Keeping expert priors — honest negative result.`,
  );
  process.exit(3);
}

// --- adopt: write fitted full-feature weights + updated eval ---
const WEIGHTS = {};
ALL_FEATURES.forEach((k, i) => (WEIGHTS[k] = round(w[i], 4)));
const meta = {
  corpus: {
    phishing: phishRows.length,
    benignHomepages: benignOther.length,
    benignLogins: benignLogins.length,
    level: "full-page-dom",
  },
  fittedFeatures: ALL_FEATURES,
  metrics: { warn: { threshold: THR, ...domMetrics }, benignLoginFalsePositives: loginFpDom },
};
const body = `// Kedayam — phishing-classifier weights (AUTO-GENERATED by bun run train:classifier:dom).
//
// DO NOT edit by hand. ALL features fitted on a FULL-PAGE DOM corpus
// (${phishRows.length} phishing + ${benignOther.length} benign homepages + ${benignLogins.length} benign login pages),
// monotonic/non-negative. Adopted because it beat the URL-only model without
// regressing on benign login pages. Metrics in ${EVAL_OUT}.
export const BIAS = ${round(b, 4)};
export const WEIGHTS = Object.freeze(${JSON.stringify(WEIGHTS, null, 2)});
export const CLASSIFIER_META = Object.freeze(${JSON.stringify(meta, null, 2)});
`;
writeFileSync(WEIGHTS_OUT, body);
writeFileSync(
  EVAL_OUT,
  JSON.stringify({ ...meta, warn: { threshold: THR, ...domMetrics } }, null, 2) + "\n",
);
spawnSync("bunx", ["prettier", "--write", WEIGHTS_OUT], { stdio: "inherit" });
console.log(`[dom] ADOPTED DOM-fitted weights → ${WEIGHTS_OUT}`);
