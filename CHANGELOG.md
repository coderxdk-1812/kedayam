# Changelog

## [Unreleased] — 2026-07-10 — ClickFix hardening + DOM-corpus attempt

### Added — ClickFix hardening (Tier-1)
- **Deferred / on-click clipboard writes** are now caught: the main-world shim
  hooks `navigator.clipboard.write()` (ClipboardItem) and
  `DataTransfer.prototype.setData` (the copy-event / button-click variant), not
  just `writeText`/`execCommand`.
- **One-click "Clear my clipboard"** action in the ClickFix modal — overwrites the
  planted command under the user's click (a real gesture, so it reliably works),
  with an inline "Clipboard cleared ✓" confirmation. Shared `SAFE_CLIPBOARD_TEXT`.
- **Broader signatures**: `irm`/Invoke-RestMethod, `schtasks`, `wmic`, `conhost`,
  AV-evasion (`Add-MpPreference`/`-ExclusionPath`/AMSI), `.hta`, python/node/perl
  download-and-run one-liners; more lure phrasings (⊞ glyph, "paste this code",
  "checking your browser", fake Cloudflare "Ray ID"). +6 clipboard tests.

### Explored — DOM-feature corpus to lift classifier recall (honest negative result)
- New `scripts/train-classifier-dom.mjs` (`bun run train:classifier:dom`): crawls
  live pages, extracts real DOM features, and fits ALL weights — with a
  **methodological guard** (benign LOGIN pages in the corpus + adopt-only-if it
  beats the current model without regressing on login-page false positives).
- Live crawl yielded only **72 usable phishing pages + 3 benign login pages**
  (most phishing hosts dead; login pages bot-walled). Too thin to fit DOM weights
  safely, so the trainer **kept the expert priors** — the guard working as
  designed (fitting on that would overfit "password field = phishing"). Classifier
  recall unchanged at the measured 0.62; infra is ready for a curated corpus.

## [Unreleased] — 2026-07-10 — Roadmap features (classifier, feed snapshot, cross-browser)

New detection depth + reach, all local and key-less. 657 tests pass (+25).

### Added
- **On-device phishing classifier** (`lib/phishingClassifier.js`): a bundled
  logistic model over URL + DOM structure (punycode, abused TLD, deep subdomains,
  digit-heavy host, off-origin login form, obfuscated payloads, credential-lure
  tokens, brand-in-subdomain). Scores page *structure*, so it flags zero-day kits
  with no known brand keyword. Pure/local/no-inference-calls, explainable
  (top feature contributions), and FP-safe by construction (trusted roots
  short-circuit; escalates as behavioral evidence only). Wired into the trust
  engine + `mlPhishingClassifier` feature flag. 16 tests incl. FP guards.
- **Build-time threat-feed snapshot** (`scripts/fetch-threat-feeds.mjs` →
  `lib/rules/blocklistSnapshot.js`): bakes ~12k deduplicated known-bad hosts from
  the FREE feeds (URLhaus, Phishing Army) into the signed bundle for day-one
  offline coverage — the hand seed was a placeholder. Safelist-filtered so a
  legitimate root (e.g. github.com, which the raw feed listed) is never shipped
  as blocked. Deliberate, committed step (`bun run feeds:snapshot`), not per-build.
- **Cross-browser packaging** (`scripts/build-crossbrowser.mjs`,
  `scripts/lib/firefoxManifest.mjs`, `bun run build:crossbrowser`): emits
  deterministic Chrome / Edge / Firefox zips. Edge is byte-identical to Chrome;
  Firefox gets a pure, unit-tested Gecko manifest transform (event-page
  background, `browser_specific_settings`, Chrome-only keys stripped). Firefox zip
  still needs a `web-ext` runtime pass before submission (see STATUS known gaps).

### Notes
- Exported `KNOWN_REPUTABLE_ROOTS` + `TRUSTED_LOGIN_PROVIDERS` from the trust
  engine so the feed generator filters against the same trust sets the engine uses.
- Chrome artifact grew ~94KB (the baked snapshot); still <250KB.

## [Unreleased] — 2026-07-10 — Reproducible builds + CI hardening

Infrastructure only — no detection-logic or behavior changes; 632 tests still pass.

### Build reproducibility (byte-stable rebuilds)
- **Icons are now committed source, not build output.** `package-extension.mjs`
  no longer regenerates icons on every package (regeneration re-compresses via
  the runtime's zlib, whose bytes differ across Node/Bun versions and silently
  churned the tracked PNGs — and, because icons ship inside the zip, made the
  archive non-reproducible). New `bun run icons` script regenerates deliberately;
  `validate:extension` no longer regenerates them either.
- **Deterministic zip** (`package-extension.mjs`): stages a copy, pins every
  entry mtime to a fixed 1980 epoch, adds files in sorted order, and uses
  `zip -X` — so repeated builds (and macOS vs Linux CI) produce byte-identical
  `public/kedayam.zip`.
- **Deterministic release cert** (`release-certify.mjs`): dropped the
  `generatedAt` timestamp and pinned `meanDetectionMs` to a static measured
  figure (the live profile run varied run-to-run). The cert is now a pure
  function of source, so the CI drift gate on it can actually pass.
- **Untracked non-reproducible evidence**: `public/kedayam-profile.json` and
  `public/kedayam-security-report.json` are now gitignored (regenerated per run,
  not shipped, not served by the site — only `kedayam.zip` is downloaded).

### CI (`.github/workflows/release-verify.yml`)
- Added gates before the existing build+drift check: `lint`, `validate:extension`,
  and the end-to-end Playwright spec (installs Chromium, runs `test:e2e`).

### Fixed
- **E2E spec now actually runs** (`tests/e2e/extension.spec.ts`): loads the MV3
  extension via `channel: "chromium"` (full-Chromium new headless — the default
  headless-shell can't load extensions/service workers) and drops the
  disallowed in-service-worker dynamic `import()`; engine scoring stays in the
  unit suite. Both e2e tests green.
- Cleared the prettier/eslint baseline (`eslint . --fix`) so the new lint gate
  is green; added `engines.node >= 20`.

## [1.1.0] — 2026-06-23

World-class freeware upgrade — phishing + malware + scam coverage with no API
keys, no telemetry, and low false positives.

### Added — modern-threat detection layers (all local, key-less)
- **ClickFix / FakeCaptcha guard** (`lib/clipboardGuard.js`): detects pages that
  copy a PowerShell / `mshta` / `curl|bash` / LOLBin command to the clipboard
  and lure the user to run it; hard-blocks with a redacted preview and a
  best-effort clipboard neutralization. Hooks `clipboard.writeText` /
  `execCommand('copy')` via the MAIN-world shim.
- **Freeware threat blocklist** (`lib/threatFeed.js`, `lib/rules/blocklistSeed.js`):
  bundled offline list → reputation works with zero network/keys; opt-in refresh
  from FREE feeds (URLhaus, Phishing Army, OpenPhish).
- **URL reputation** (`lib/urlReputation.js`): abused/free TLDs, URL shorteners,
  phishy path tokens, **brand-domain-as-subdomain** spoof, and **TLD-swap**
  (right brand, wrong TLD).
- **IDN mixed-script / confusable** (`lib/idnConfusable.js`): flags hostnames
  mixing Latin with Cyrillic/Greek/Armenian glyphs.
- **Open-redirect laundering** (`lib/openRedirect.js`): detects
  `?url=`/`redirect=` parameters bouncing to a different site (escalates on
  encoded / IP / credential-bearing targets).
- **Malicious-download guard** (`content/content.js`): warns before executable
  downloads on low-trust pages.
- **Tech-support-scam / scareware guard** (`lib/scarewareGuard.js`): warns on
  fake "your PC is infected — call this number" pages (alarmist text + call-to-
  action / fullscreen-lock).
- New Options toggles + a "Threat feed" pane (opt-in auto-update + manual refresh).

### Changed
- Trust engine + arbitration extended with new Tier-0 identity/reputation rules;
  new signals count as behavioral evidence so they survive the trusted-root floor
  but never fire on legitimate brands.
- Manifest `version` → 1.1.0; description rewritten (freeware, ClickFix, scams).
- README / PRIVACY / PERMISSIONS updated; no new permissions requested.

### Tests / release
- **632 tests pass** (added unit + redteam coverage for every new module, plus
  false-positive guards: github / google / wikipedia / normal `.xyz` stay Safe).
- Rebuilt signed `public/kedayam.zip`; regenerated release cert
  (`browserStoreReady: true`) with matching sha256.

## [1.0.0]

Initial Manifest V3 release: trust engine, lookalike/clone detection,
sensitive-data paste/file guards, permission monitoring, options/popup UI.
