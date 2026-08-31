# Kedayam Browser Shield — Status

Last updated: 2026-08-31

> **2026-08-31 (v1.1.3) — "Always trust this site" + VirusTotal second opinion:** flag
> modals and the popup now offer permanent trust (adds the registrable root to
> `settings.allowlist` via the new `trustPermanent` message, two-click confirm,
> removable in Options) and a "Check this domain on VirusTotal" link that passes
> the origin only, rendered as a full-width CTA; session-only trust removed from
> the verdict modals. 703 unit + 6 e2e green. Shipped as **v1.1.3** with rebuilt + certified artifacts.
>
> **2026-07-28 (v1.1.2) — genuine HDFC / multi-domain-bank false positive fixed:**
> a tester screenshot showed the real HDFC NetBanking login
> (`now.hdfc.bank.in`) flagged **MEDIUM RISK · 20/100** as brand-impersonation
> ("mentions hdfcbank.com but is not on that domain"). Two compounding bugs:
> (1) `bank.in` was missing from the public-suffix list, so `now.hdfc.bank.in`
> collapsed to `bank.in` instead of the real root `hdfc.bank.in`; (2) HDFC's
> brand entry only whitelisted `hdfcbank.com`, so referencing it from HDFC's own
> `.bank.in` domain looked off-domain. Added `bank.in` (IDRBT/RBI registry) as a
> public suffix and the `<bank>.bank.in` aliases for HDFC/ICICI/Axis/Kotak/SBI.
> Genuine bank logins now **safe**; off-domain lookalikes still **dangerous**.
> **695 tests green** (+2 regressions).
>
> **2026-07-28 (v1.1.1) — "scan not visible / UNAVAILABLE" fixed:** root cause was
> `scan.tabId` validation bounded at `< 1e7`; Chrome tab ids exceed 10M on
> long-lived profiles, so the popup's scan was rejected (`invalid:scan.tabId`).
> Now accepts any safe-integer id + URL-only popup fallback. This is the real fix
> for the "trust score doesn't load" report.
>
> **2026-07-28 — tester-reported fixes shipped:** DOM-context login false
> positives fixed (ungated `phishing.cap=60` removed; `credential-form` →
> informational; benign "sign in" no longer "urgent"; `auth-keyword` gated to the
> registrable label) → unlisted bank/SSO/SaaS logins now **safe**, phishing
> unchanged. Warning modals gained a working **"Leave this page"** button. Popup:
> cold-SW retry + clearer non-scannable copy + richer explanation. New **local**
> "threats prevented" counters (popup Activity tab; zero telemetry) + Cloudflare
> metrics guide (`CLOUDFLARE_METRICS.md`). **693 tests green** (+9 regressions).

MV3 Chrome extension (`extension/`) — freeware, key-less, local-only phishing +
malware + data-leak protection. Shippable artifact: `public/kedayam.zip`.

> **Full reality-check, comparison matrix, and prioritized roadmap live in
> `STATUS.html`** (render it in a browser). Summary below.

## Real-world value (honest)

Every Chrome user already has Google Safe Browsing (huge cloud backend), so
Kedayam's worth is what it adds **on top** as a defense-in-depth layer — not a
replacement.

- **High, differentiated uplift:** ClickFix / fake-CAPTCHA **clipboard-malware
  guard** (AV & Safe Browsing miss it — user self-runs the payload); **sensitive-
  data paste/PII leak guard**; **100% local, zero-telemetry** with explainable
  on-page warnings.
- **Medium uplift:** homoglyph/IDN visual spoofs, brand-in-subdomain, abused-TLD,
  open-redirect.
- **Weaker than incumbents:** blocklist scale (12k vs. millions), no default cloud
  intelligence, and the classifier — now **measured** (P 0.98 / R 0.62 / FP 1.4%
  @warn on host-shape) — catches structural phishing but **misses ~40% of kits that
  look benign by hostname** (that's why it's a corroborating layer, not standalone).
- **Best for:** ClickFix-targeted users, anyone handling secrets/PII (devs,
  finance, support), and privacy-conscious users who won't run cloud AV tools.

## What next (prioritized — see STATUS.html for detail)

1. **Tier 1 (most ROI):** ~~train + measure the classifier~~ ✅ (P 0.98 / R 0.62 /
   FP 1.4% @warn); ~~harden ClickFix~~ ✅ (deferred-write hooks + one-click clear +
   broader signatures); **DOM-corpus recall lift attempted** ⚠️ — infra built with a
   login-page guard, but the live crawl was too thin (72 phishing + 3 login pages)
   so priors were kept (no regression). **Next:** a curated saved-HTML phishing
   corpus for the DOM fit; bigger signed delta-updated blocklist with
   privacy-preserving (hash-prefix / k-anonymity) refresh; redirect-chain resolution.
2. **Tier 2:** optional privacy-preserving cloud reputation; AiTM/reverse-proxy
   phishing detection; punycode banner; community FP loop; i18n; Firefox runtime
   validation; a11y pass.
3. **Tier 3 (credibility):** published reproducible benchmark vs. Safe Browsing /
   Netcraft; independent audit + build attestation; tighten permissions.

## Shipped

- **Trust-score false-positive fix (2026-07-17)**: legit sites no longer read
  "suspicious ~65". Raised `BASELINE` 50→62, removed the blanket unknown-login
  soft-cap, gated arbitration `unknown-login`/`unknown-auth` on corroboration,
  and stopped `brand-impersonation` / `unknown-auth-workflow` from firing on
  bare brand mentions or header "Sign in" links. Real-DOM after fix: BBC / HN /
  StackOverflow / Reddit / gov.uk → **77 safe**, Wikipedia / GitHub → **100
  safe**; all phishing corpora still **0/dangerous**. Verified by loading the
  live extension in a real browser.
- Detection engine v1.1.0: threat blocklist, lookalike/homoglyph, IDN mixed-script,
  URL reputation (abused TLD / shortener / brand-subdomain / TLD-swap), open-redirect,
  clone/phishing DOM, auth-flow arbitration, explainable 0–100 verdict.
- **In-product Transparency panel** (`lib/protectionCatalog.js` → Options
  "Protection" tab): shows every layer with a plain-English description, an honest
  HIGH/MED/LOW uplift rating, live on/off state, and its honest limit — plus the
  product-wide limits. Same candid assessment users see and devs do. e2e-verified.
- **On-device phishing classifier** (`lib/phishingClassifier.js`), **weights fitted
  & MEASURED** on a 12k labeled corpus (`bun run train:classifier`): host-shape
  weights learned (non-negative/monotonic), runtime features keep expert priors.
  Measured @warn: **precision 0.98, recall 0.62, FP 1.4%**; @block: P 0.99, R 0.52,
  FP 0.5%. Replaced the old placeholder recall in the cert. Local, explainable,
  FP-safe (trusted roots short-circuit; high-precision operating points).
- **Build-time threat-feed snapshot**: ~20k known-bad hosts baked in from URLhaus +
  Phishing Army (`bun run feeds:snapshot`, PhishTank optional), safelist-filtered.
- **Ad & tracker blocker** (`declarativeNetRequest`, default on, toggleable):
  ~3.5k ad/tracker domains blocked locally (`bun run adblock:rules`), safelist-
  filtered, sub-resources only. First new permission since launch.
- **Shareable promo image**: `public/kedayam-promo.png` (1080×1350) via
  `bun run promo:image` — colorful feature/benefit poster for social circulation.
- **Cross-browser packaging**: deterministic Chrome / Edge / Firefox zips
  (`bun run build:crossbrowser`); Edge byte-identical to Chrome, Firefox via a
  unit-tested Gecko manifest transform.
- Page-runtime guards: paste/file/permission, **hardened ClickFix clipboard**
  (deferred `clipboard.write`/`setData` hooks + one-click "clear clipboard" +
  broader command/lure signatures), download, scareware.
- **681 unit/redteam/compat tests green** (full per-file results in
  [`test.html`](test.html), regenerate with `bun run test:report`); ESLint/prettier
  clean; validator clean.
- **Byte-reproducible build**: icons are committed source; zip is deterministic
  (fixed mtimes + sorted + `-X`); release cert is a pure function of source.
- **CI** (`release-verify.yml`, **green**): lint → validate:extension → tests →
  e2e → verify-artifact (contents match source) → certify (byte-reproducible).
- **E2E** (`tests/e2e/extension.spec.ts`): loads MV3 extension via `channel:"chromium"`;
  2/2 green, wired into CI.

## Pending / Backlog

- Store logistics: Privacy Policy URL **live** (https://kedayam.lovable.app/privacy),
  440×280 promo tile + permission justification + data-handling disclosures
  **done** (per submitter 2026-07-17); still need a **1280×800 screenshot**
  (Chrome Web Store requires ≥1) and the dev account ($5 + ID verification).
- **Firefox runtime validation**: `web-ext lint` + load the generated
  `kedayam-firefox.zip` (background-ESM support varies by FF version).
- **i18n** of warning copy (`_locales/`, Hindi/EU langs) — not started.
- **Community false-positive loop** (local "mark safe" → per-domain trust floor)
  — engine has `trustFloor`/learned-safe hooks; UI + storage wiring not started.
- **Redirect-chain expansion** for shorteners (score the true landing via the
  existing webRequest redirect tracking) — not started.
- Punycode/IDN decoded-host banner (data exists in `confusable`; UI not started).

## Known gaps & caveats

- Broad `host_permissions` (`http/https://*/*`) + `webRequest` + `tabs` → Web Store
  extended review; needs a tight single-purpose justification.
- The committed zip is a checked-in binary built on macOS; the `zip` CLI is not
  byte-identical across OSes, so CI verifies the zip's *contents* match source
  (`scripts/verify-artifact.mjs`) rather than a byte-for-byte rebuild. The release
  cert stays byte-reproducible (pure function of source). CI is green.
- E2E covers load/runtime smoke + popup render; engine scoring stays in unit tests
  (dynamic `import()` is disallowed inside a running service worker).
