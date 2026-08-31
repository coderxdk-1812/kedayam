# Changelog

## [1.1.3] — 2026-08-31 — "Always trust this site" + VirusTotal second opinion

- **Permanent trust from the warning modal.** The flag modals (hard + soft) now
  offer **"Always trust this site"** next to the session-only button. It sends a
  new `trustPermanent` message; the background derives the *registrable root*
  (content scripts only ever report their own hostname, so a page can't smuggle
  an arbitrary root), appends it to `settings.allowlist` (cap 500), sets a
  session override, logs the decision, and force-rescans the tab so the badge
  updates immediately. Allowlisted roots are already a trust primitive in the
  engine, so the domain stops being flagged; it stays removable in
  **Options → Allowlist**. The button requires a second click to confirm, so one
  mis-click can't permanently silence the scanner. The content script also
  suppresses trust banners/modals for allowlisted roots locally — paste, file and
  clipboard protections (which guard the user's own data, not the site's
  reputation) stay active.
- **VirusTotal check, as a full-width CTA.** The modal and the popup both show a
  **🔎 Check this domain on VirusTotal** button spanning the dialog width, above
  the decision buttons, so verifying reads as the first move rather than a
  footnote. Opens in a new tab (`rel="noopener noreferrer"`) at
  `virustotal.com/gui/search?query=<url>`. Only the **origin** is handed over —
  never the path or query string, which can carry session tokens or PII.
- **"Trust this site for the session" removed from the trust-verdict modals.**
  Leave / verify / always-trust / continue-once are the meaningful choices; a
  fifth button diluted them. Session trust still exists on the paste, file and
  ClickFix modals, where it means "stop re-prompting me on this site for this
  session", and the popup's session-trust button was dropped for the same reason.
- **Popup** gained the matching **Always trust** button + VirusTotal CTA, both
  hidden on browser-internal pages that can't be scanned.
- Tests: `tests/unit/permanentTrust.test.js` (schema validation, allowlisted root
  no longer flagged, VirusTotal URL shape + no path/query leak);
  `isolationHardening` updated for the new trust-mutation type. **703 green.**

## Unreleased — 2026-07-29 — Dev-dependency ReDoS advisory + artifact re-verify

- **`brace-expansion` pinned to `^2.0.2`** via a `package.json` `overrides` field
  (resolves to 2.1.2) to clear the CVE-2025-5889 ReDoS advisory surfaced by
  `npm audit`. It is a **dev-only transitive** dep (eslint → minimatch →
  brace-expansion) and is **not present in the shipped extension** — `kedayam.zip`
  bundles only `extension/` source, no `node_modules`. Fixed out of hygiene for
  security review. `bun run lint` verified clean with brace-expansion 2.x; did
  **not** use `npm audit fix --force` (would risk a breaking eslint major and
  desync from the bun lockfile).
- **Release artifact re-verified, not stale.** Rebuilt `public/kedayam.zip` via
  `node scripts/release-build.mjs` (695 tests green) + `release-certify.mjs`; the
  zip, `.sha256`, and cert reproduced **byte-for-byte identical** to `main`, so
  the drift gate already passes on HEAD (`[verify-artifact] OK — 69 files`). Any
  CI "stale artifact" failure was on a branch behind the v1.1.2 fixes, not HEAD.

## [1.1.2] — 2026-07-28 — Fix genuine HDFC / multi-domain-bank false positive

A tester screenshot showed the **real** HDFC NetBanking login page
(`now.hdfc.bank.in`) flagged as **MEDIUM RISK · 20/100** with the signal
"Page mentions hdfcbank.com but is not on that domain — Authentication risk:
critical". HDFC legitimately operates on two registrable domains
(`hdfcbank.com` and, for its live Keycloak NetBanking realm, `hdfc.bank.in`),
and two compounding bugs turned that into a brand-impersonation hit:

1. **`bank.in` was missing from the public-suffix list** (`lib/lookalike.js`).
   `rootDomain("now.hdfc.bank.in")` collapsed to `bank.in` instead of the real
   registrable root `hdfc.bank.in`. `.bank.in` is an IDRBT/RBI-managed registry —
   every Indian bank gets a name under it — so it is a public suffix.
2. **HDFC's brand entry only whitelisted `hdfcbank.com`**
   (`lib/phishingHeuristics.js`). Referencing that brand from HDFC's own
   `.bank.in` domain read as off-domain, and with a password field present the
   `brand-impersonation` signal (weight 50, authRisk critical) fired.

Changes:
- `lib/lookalike.js`: added `bank.in` to `PSL_TWO_LEVEL`.
- `lib/phishingHeuristics.js`: added `<bank>.bank.in` to `TRUSTED_LOGIN_PROVIDERS`
  and to the `BRAND_KEYWORDS` aliases for HDFC / ICICI / Axis / Kotak / SBI.
- `tests/calibration/loginPageFalsePositives.test.js`: +2 regressions — genuine
  `now.hdfc.bank.in` reads **safe**; an off-domain `.bank.in`-style lookalike
  (`hdfc-secure-login.example`) still reads **dangerous** with `brand-impersonation`.
- Bumped manifest + popup footer to **v1.1.2**; rebuilt `public/kedayam.zip`
  (sha `2889adf1…`) + cross-browser zips; release-cert + drift gate re-verified.
- **695 tests green** (was 693), lint clean.

## [1.1.1] — 2026-07-28 — Fix "scan not visible / UNAVAILABLE" (invalid:scan.tabId)

**Root cause found from a tester screenshot** showing the popup stuck on
"UNAVAILABLE" with the error `invalid:scan.tabId`. The message-schema validator
bounded `scan.tabId` with `isInt` (`< 1e7`), but **Chrome tab ids increment
across the whole browser lifetime** and on a long-lived profile easily exceed 10
million. A legitimate large tab id was rejected, so the popup's scan message
never ran and the trust score never loaded. (Earlier in-browser testing used a
fresh profile with small ids, which is why it wasn't caught then.)

- `lib/messageSchemas.js`: `scan.tabId` now validates with `isBrowserId`
  (`Number.isSafeInteger(v) && v >= 0`) — accepts real tab ids, still rejects
  negatives / non-integers / unsafe values.
- `popup/popup.js`: added a URL-only fallback scan (no tabId) so any future
  validation hiccup degrades to a working score instead of "UNAVAILABLE".
- Bumped extension **version 1.1.0 → 1.1.1** so the fixed build is visibly
  identifiable (the reported screenshot showed a stale v1.0.0 footer).
- Verified in a real Chromium build with a large stubbed tab id (987654321):
  popup now loads **100 / Safe**. 693 tests (+2 tabId regressions).

## [Unreleased] — 2026-07-28 — Tester-reported fixes (FP calibration, popup, warning buttons, metrics)

Addressed five issues a tester reported. Verified in a real Chromium build via
Playwright (`channel: "chromium"`) and 691 unit tests (was 682; +9 regressions).

### Fixed — legit sites still reading medium-risk (issue #1, "NEW-04")
The 2026-07-17 pass fixed URL-only scoring but **DOM-context** login pages still
fell into "suspicious". Root-caused by scoring live/synthetic login pages:

- **Ungated `phishing.cap = 60`** (`phishingHeuristics.js`): a hard 60-cap was
  applied to **any** credential form, bypassing the corroboration gate added in
  July. Now the bare-credential-form branch caps only when the page's own
  heuristic stack is independently confident (≥0.6); escalation is otherwise
  owned by arbitration's corroboration gate. *This was the primary cause.*
- **`credential-form` penalty → informational** (`phishingHeuristics.js`): the
  mere presence of a password form on an unlisted domain dropped from weight 25
  (−21) to **weight 0** (informational). The `credentialHarvest` flag that drives
  arbitration is unchanged, so phishing detection is untouched.
- **Benign login copy no longer "urgent"** (`phishingHeuristics.js`): split out
  `URGENT_AUTH_PHRASES` (coercive only — "verify your account", "unusual
  activity", "account suspended"). Plain "sign in"/"log in"/"login" no longer
  fires the `auth-phrasing` penalty.
- **`auth-keyword` gated to the registrable label** (`trustEngine.js`): `login`/
  `secure`/`account`/`verify` in a **subdomain** (`login.company.com`,
  `secure.bank.com`) no longer penalizes — only when baked into the registrable
  domain itself (`paypal-login.com`, `verify-portal.tld`).
- **Latent bug fixed**: `hidden-login-fields` read `hiddenCount`/`fieldsCount`
  but the sanitized pipeline uses `hiddenFields`/`fieldCount` — it never fired in
  production. Now reads both spellings and fires on a high hidden **ratio** too.

Result (real-DOM): unlisted bank / company SSO / unlisted SaaS logins →
**72–77 safe**; off-domain POST, lookalike, brand-impersonation, coercive
phrasing → still **0–37 dangerous**. All phishing corpora unchanged.

### Fixed — warning-modal action buttons did nothing useful (issue #4)
`content/content.js`: buttons fired (verified), but "Go back" only dismissed the
modal, leaving the user on the hostile page — so it read as broken. Added a real
**"Leave this page"** action (`onLeave` → `leaveToSafety()`: `history.back()`
with an `about:blank` hard-replace fallback) wired into both the hard and soft
trust modals. Delegation now uses `closest("[data-act]")` so a click on any
child node still registers. Paste/file/permission modals keep "Go back" = cancel.

### Improved — popup trust score & explanation (issues #2, #3)
- `popup/popup.js`: retry the scan once on a cold service worker before showing
  an error; clearer copy for non-scannable pages (chrome://, new tab, files,
  store) so an empty score no longer reads as "broken". (The popup already loads
  the score correctly on real http(s) tabs — confirmed in-browser.)
- `lib/explanation.js`: every verdict now lists the concrete contributing
  factors — for safe pages it cites the positive signals (encrypted connection,
  known-reputable domain, prior safe use) instead of a bare "looks safe".

### Added — local, privacy-safe metrics (issue #5, "threats prevented")
- `lib/storage.js` `bumpMetric()`/`getMetrics()`: on-device counters
  (`threatsPrevented`, `pastesBlocked`, `clickfixBlocked`) — no URLs, no PII,
  nothing uploaded. Bumped in `background.js`; shown in the popup Activity tab.
- `CLOUDFLARE_METRICS.md`: guidance for the tester — local counters (recommended),
  Chrome Web Store install stats, Cloudflare Web Analytics + Full(strict) SSL for
  site downloads, and a ready-to-deploy opt-in aggregate Worker (KV) if wanted.

## [Unreleased] — 2026-07-17 — Trust-score false-positive fix (legit sites read "safe")

### Fixed — the "every good site scores ~65 / suspicious" false-positive
Root-caused after loading the extension in a real browser and scoring live
pages. Three compounding causes, all corrected; real-DOM scores after the fix:
BBC News, Hacker News, StackOverflow, Reddit, gov.uk → **77 safe**; Wikipedia,
GitHub → **100 safe**. All phishing corpora still score **0/dangerous**.

- **Baseline too low** (`trustEngine.js`): `BASELINE` 50 → **62**. A clean
  HTTPS site with zero risk signals now lands in the safe band (≥71) instead of
  65/suspicious. Being *unknown* is a ranking, not a warning — reputable roots
  still reach ~100 and outrank unknown-but-clean sites.
- **Blanket login soft-cap removed** (`trustEngine.js`): the unconditional
  `min(score, 65)` on any unknown auth page is gone. Whether a sign-in page is
  capped is now owned solely by the corroboration-gated arbitration rules.
- **Arbitration `unknown-login` / `unknown-auth` now require corroboration**
  (`arbitration.js`): a clean, same-origin HTTPS login (a bank, unlisted SaaS,
  company SSO) stays safe; the cap fires only when an independent risk cue
  agrees (external POST, lookalike, IDN, clone, new domain, insecure transport,
  abused TLD, hidden overlay, email-first).
- **`brand-impersonation` no longer fires on a bare brand mention**
  (`phishingHeuristics.js`): merely mentioning/linking to a brand (news, blogs,
  forums, aggregators like Hacker News) is not impersonation. It now requires an
  actual credential prompt (password / OTP / OAuth) on a non-brand domain.
- **`unknown-auth-workflow` requires a real auth-form element**
  (`phishingHeuristics.js`): a "Sign in" link in a site header (auth *text*
  only) no longer penalizes the page; an OTP/OAuth credential element is needed.
- **Docs/UI:** `PERMISSIONS.md` now correctly documents `declarativeNetRequest`
  (was still listed under "we do NOT request"); popup footer version reads from
  the manifest instead of a hardcoded `v1.0.0`.
- Tests: recalibrated 2 expectations to the new posture, added 2 guard tests;
  **681 passing**. Release artifact + cross-browser zips rebuilt and re-certified.

## [Unreleased] — 2026-07-10 — Ad/tracker blocker + wider phishing bake + promo asset

### Added — ad & tracker blocker (first new permission)
- **`declarativeNetRequest`-based ad/tracker blocking**, default ON, toggleable in
  Options. Bundles a free ad/tracker domain list (Peter Lowe) as a compact DNR
  static ruleset (`extension/rules/adblock-rules.json`, ~3.5k domains in 4 rules)
  generated by `bun run adblock:rules`. Blocks sub-resources only (never the
  top-level page), safelist-filtered so reputable roots are never blocked. 100%
  local — no browsing data leaves the device. Runtime toggle via
  `chrome.declarativeNetRequest.updateEnabledRulesets` in the background worker.
- This is the extension's **first new permission** since launch;
  `declarativeNetRequest` is the review-friendly MV3 standard and the cert's
  permission allowlist was updated accordingly.

### Changed — wider phishing coverage (privacy-safe, keyless)
- Build-time threat-feed snapshot raised **12k → 20k** hosts and can now pull
  **PhishTank** as an optional source (`PHISHTANK_APP_KEY`; skipped gracefully
  without a key). Still a pure BUILD-time bake — no runtime network, no URLs ever
  leave the device. (Real-time cloud URL submission was deliberately NOT added, to
  keep the zero-telemetry promise; the opt-in Google Safe Browsing path remains.)

### Added — shareable promo asset
- `public/kedayam-promo.html` + rendered `public/kedayam-promo.png` (1080×1350 @2×,
  Instagram/WhatsApp-ready) via `bun run promo:image` — colorful feature/benefit
  poster with a security + privacy focus.

### Tests
- +6 ad-blocker unit tests (rule builder + shipped ruleset) and a 4th e2e test
  proving the DNR ruleset ships enabled in a real browser. 680 unit + 4 e2e green.

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
