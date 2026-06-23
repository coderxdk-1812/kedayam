# Kedayam Browser Shield — Project Context

Last updated: 2026-06-23

## Pending

- **Store-submission logistics** (not code): host a public Privacy Policy URL,
  produce ≥1 screenshot (1280×800) + a 440×280 promo tile, register the
  Chrome Web Store developer account ($5 + ID verification), fill the
  data-handling disclosures. Broad `host_permissions` will trigger extended review.
- **Build-time threat-feed snapshot**: bake a large URLhaus + Phishing Army
  snapshot into each release so day-one offline coverage is thousands of hosts,
  not just the seed in `lib/rules/blocklistSeed.js`.
- **On-device ML phishing classifier** (TF.js/ONNX, bundled, local-only).
- **E2E tests**: `tests/e2e/` is configured (Playwright) but empty.
- **CI**: no `.github/workflows/`; add validate → test → certify on push.
- **Cross-browser builds** (Firefox/Edge manifests) + i18n of warning copy.
- **Toolchain note**: tests/build require Node 20+ (repo default shell may be
  Node 18, which the installed Vitest/Vite reject). Use
  `~/.nvm/versions/node/v22.x/bin` or add `.nvmrc` / `engines`.

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
