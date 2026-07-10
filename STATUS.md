# Kedayam Browser Shield — Status

Last updated: 2026-07-10

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
  intelligence, and the classifier is a **hand-tuned heuristic whose recall is not
  yet measured** (the cert's 0.95 is a placeholder).
- **Best for:** ClickFix-targeted users, anyone handling secrets/PII (devs,
  finance, support), and privacy-conscious users who won't run cloud AV tools.

## What next (prioritized — see STATUS.html for detail)

1. **Tier 1 (most ROI):** train + measure the classifier on a real labeled corpus
   and publish precision/recall; harden ClickFix (deferred clipboard + one-click
   clear); bigger signed, delta-updated blocklist with privacy-preserving
   (hash-prefix / k-anonymity) refresh default-on; redirect-chain resolution.
2. **Tier 2:** optional privacy-preserving cloud reputation; AiTM/reverse-proxy
   phishing detection; punycode banner; community FP loop; i18n; Firefox runtime
   validation; a11y pass.
3. **Tier 3 (credibility):** published reproducible benchmark vs. Safe Browsing /
   Netcraft; independent audit + build attestation; tighten permissions.

## Shipped

- Detection engine v1.1.0: threat blocklist, lookalike/homoglyph, IDN mixed-script,
  URL reputation (abused TLD / shortener / brand-subdomain / TLD-swap), open-redirect,
  clone/phishing DOM, auth-flow arbitration, explainable 0–100 verdict.
- **On-device phishing classifier** (`lib/phishingClassifier.js`): bundled logistic
  model over URL/DOM structure — catches zero-day kits with no brand keyword. Local,
  explainable, FP-safe (trusted roots short-circuit).
- **Build-time threat-feed snapshot**: ~12k known-bad hosts baked in from URLhaus +
  Phishing Army (`bun run feeds:snapshot`), safelist-filtered.
- **Cross-browser packaging**: deterministic Chrome / Edge / Firefox zips
  (`bun run build:crossbrowser`); Edge byte-identical to Chrome, Firefox via a
  unit-tested Gecko manifest transform.
- Page-runtime guards: paste/file/permission, ClickFix clipboard, download, scareware.
- **657 unit/redteam/compat tests green**; ESLint/prettier clean; validator clean.
- **Byte-reproducible build**: icons are committed source; zip is deterministic
  (fixed mtimes + sorted + `-X`); release cert is a pure function of source.
- **CI** (`release-verify.yml`, **green**): lint → validate:extension → tests →
  e2e → verify-artifact (contents match source) → certify (byte-reproducible).
- **E2E** (`tests/e2e/extension.spec.ts`): loads MV3 extension via `channel:"chromium"`;
  2/2 green, wired into CI.

## Pending / Backlog

- Store logistics: hosted Privacy Policy URL (page exists, must deploy),
  1280×800 screenshot + 440×280 promo tile (none yet), dev account ($5 + ID),
  data-handling disclosures, broad-permission justification.
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
