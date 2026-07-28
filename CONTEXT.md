# Kedayam Browser Shield — Project Context

Last updated: 2026-07-28

## Pending

- **Store-submission logistics** (not code): Privacy Policy URL is now **live**
  (https://kedayam.lovable.app/privacy); 440×280 promo tile, permission
  justification, and data-handling disclosures are **done** (submitter,
  2026-07-17). Still outstanding: **≥1 screenshot (1280×800)** for the listing
  and the Chrome Web Store **developer account** ($5 + ID verification). Broad
  `host_permissions` + `webRequest` will still trigger extended review.
- **Firefox runtime validation**: `web-ext lint` + load `kedayam-firefox.zip`
  (regenerated 2026-07-17 by `bun run build:crossbrowser`); background-ESM
  support varies by FF. STATUS.html correctly lists this as packaged-not-validated.
- **i18n** of warning copy (`_locales/`, Hindi/EU) — not started.
- **Community FP loop / redirect-chain expansion / punycode banner** — not started.
- **Refresh the feed snapshot per release**: `bun run feeds:snapshot` && commit
  `lib/rules/blocklistSnapshot.js` (currently ~12k hosts, pulled 2026-07-10).

### Done 2026-07-28 (v1.1.2 — genuine HDFC / multi-domain-bank false positive)
- Tester screenshot: real HDFC NetBanking login (`now.hdfc.bank.in`) flagged
  **MEDIUM RISK 20/100** as brand-impersonation ("mentions hdfcbank.com but is
  not on that domain"). Root cause = two bugs: (1) `bank.in` missing from the
  public-suffix list, so `rootDomain("now.hdfc.bank.in")` = `bank.in` not
  `hdfc.bank.in`; (2) HDFC brand entry only whitelisted `hdfcbank.com`. Added
  `bank.in` (IDRBT/RBI registry) to `PSL_TWO_LEVEL` and `<bank>.bank.in` aliases
  for HDFC/ICICI/Axis/Kotak/SBI. Genuine bank logins → **safe**; off-domain
  lookalikes still **dangerous**. Bumped to v1.1.2, rebuilt artifacts, drift gate
  re-verified, **695 tests green** (+2 regressions in
  `tests/calibration/loginPageFalsePositives.test.js`).

### Done 2026-07-28 (v1.1.1 — "scan not visible / UNAVAILABLE" root cause)
- Tester screenshot showed the popup stuck on **UNAVAILABLE** with
  `invalid:scan.tabId`. Root cause: `messageSchemas.js` bounded `scan.tabId` at
  `< 1e7`, but Chrome tab ids exceed 10M on long-lived profiles → the scan
  message was rejected and the score never loaded. Fixed with `isBrowserId`
  (`Number.isSafeInteger`); added a URL-only popup fallback; bumped to **v1.1.1**
  so the fixed build is identifiable. Verified in-browser with a large tab id
  (987654321) → popup loads 100/Safe. This is the actual fix for the earlier
  "trust score doesn't load in popup" report (issue #2).

### Done 2026-07-28 (tester-reported fixes — FP calibration, popup, buttons, metrics)
- **Login-page false positives (issue #1)**: the July fix handled URL-only
  scoring but DOM-context logins still read "suspicious". Root cause found by
  scoring real/synthetic login pages: an **ungated `phishing.cap = 60`** in
  `phishingHeuristics.js` capped every credential form, bypassing arbitration's
  corroboration gate. Fixed that; made `credential-form` informational (weight
  0); split `URGENT_AUTH_PHRASES` so benign "sign in/login" isn't "urgent";
  gated `auth-keyword` to the registrable domain label (not `login.*`/`secure.*`
  subdomains); fixed a latent `hidden-login-fields` field-name mismatch. Result:
  unlisted bank/SSO/SaaS logins → **72–77 safe**; all phishing still **dangerous**.
- **Warning buttons (issue #4)**: added a real **"Leave this page"** action
  (`leaveToSafety()` → history.back + about:blank fallback) to the trust modals;
  robust `closest()` delegation. "Go back" on paste/file modals still = cancel.
- **Popup (issues #2/#3)**: cold-SW retry + clearer non-scannable-page copy;
  explanation now cites concrete positive factors for safe pages. (Popup loads
  the score correctly on real http(s) tabs — verified in Chromium.)
- **Metrics (issue #5)**: local `bumpMetric`/`getMetrics` counters (threats
  prevented / pastes / ClickFix) shown in the popup Activity tab — no telemetry.
  `CLOUDFLARE_METRICS.md` documents SSL + optional opt-in aggregate Worker.
- **691 tests green** (+9 regressions in `tests/calibration/loginPageFalsePositives.test.js`),
  lint clean, 4 e2e pass. Release + cross-browser artifacts rebuilt.

### Done 2026-07-17 (trust-score false-positive fix)
- Root-caused + fixed the "every good site scores ~65/suspicious" complaint by
  loading the extension in a real browser and scoring live pages. Raised
  `BASELINE` 50→62, removed the blanket unknown-login soft-cap, gated arbitration
  `unknown-login`/`unknown-auth` on corroboration, and stopped
  `brand-impersonation` / `unknown-auth-workflow` from firing on bare brand
  mentions or header "Sign in" links. Legit sites now 77–100/safe; phishing still
  0/dangerous. 681 tests green; release + cross-browser artifacts rebuilt &
  re-certified (`kedayam.zip` sha `765d3687…`). Also fixed PERMISSIONS.md
  (`declarativeNetRequest` was mis-documented) and the popup version string.
- **Release artifact rebuilt & committed** — the earlier drift blocker is closed;
  `public/kedayam.zip` + `.sha256` + cert regenerated from current source.

### Done 2026-07-10 (roadmap features)
- **On-device phishing classifier** (`lib/phishingClassifier.js`) — bundled
  logistic model over URL/DOM structure; wired into the engine, 16 tests + FP guards.
- **Threat-feed snapshot** — ~12k hosts baked in (`lib/rules/blocklistSnapshot.js`),
  safelist-filtered; generator `scripts/fetch-threat-feeds.mjs`.
- **Cross-browser builds** — `scripts/build-crossbrowser.mjs` emits Chrome/Edge/
  Firefox zips; Firefox transform `scripts/lib/firefoxManifest.mjs` (unit-tested).

### Done 2026-07-10 (infra)
- **CI hardened**: `release-verify.yml` now runs lint → validate:extension →
  tests → e2e → build → certify → drift gate.
- **E2E works**: `tests/e2e/extension.spec.ts` loads the MV3 extension via
  `channel: "chromium"`; both tests green and wired into CI.
- **Byte-stable rebuilds**: icons are committed source (not regenerated on
  build); zip is deterministic (fixed mtimes + sorted + `-X`); cert is a pure
  function of source; profile/security-report are gitignored.
- **Node ≥20 pinned** via `engines`; prettier/eslint baseline cleared.

## Snapshot

Manifest V3 Chrome extension (`extension/`) — **freeware, key-less, local-only**
phishing + malware + data-leak protection. Vite/Bun app shell in repo root;
the shippable product is the `extension/` folder, packaged to `public/kedayam.zip`.

Pipeline (engine `lib/trustEngine.js` → `lib/arbitration.js`): threat blocklist →
lookalike/homoglyph → IDN mixed-script → URL reputation (abused TLD / shortener /
brand-subdomain / TLD-swap) → open-redirect → clone/phishing DOM → auth-flow →
explainable 0–100 verdict. Page runtime (`content/content.js`): paste/file/
permission guards, ClickFix clipboard guard, download guard, scareware guard.

Status (v1.1.0): **632/632 tests pass**, validator + ESLint clean, release cert
`browserStoreReady: true`, fresh signed zip with matching sha256.

## Decisions

- **No commercial keys.** Safe Browsing / VirusTotal remain optional + off by
  default; the bundled blocklist + heuristics are the default reputation layer.
- **Low false positives by construction.** New signals corroborate before
  escalating, respect the trusted-root floor, and are gated on auth workflows
  (e.g. abused-TLD only escalates with a login present). Verified by FP-guard
  tests (github/google/wikipedia/normal-.xyz stay Safe).
- **ClickFix clipboard scan is local + ephemeral**; only a redacted preview is
  shown. Best-effort clipboard neutralization on detection.
- **Threat-feed refresh is opt-in** (network) — default install makes zero
  outbound calls. No new permissions were added for any v1.1.0 feature.
- **Content script mirrors pure modules inline** (content scripts aren't ES
  modules); the canonical logic + tests live in `lib/`.
