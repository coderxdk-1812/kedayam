# Kedayam Browser Shield — Status

Last updated: 2026-07-10

MV3 Chrome extension (`extension/`) — freeware, key-less, local-only phishing +
malware + data-leak protection. Shippable artifact: `public/kedayam.zip`.

## Shipped

- Detection engine v1.1.0: threat blocklist, lookalike/homoglyph, IDN mixed-script,
  URL reputation (abused TLD / shortener / brand-subdomain / TLD-swap), open-redirect,
  clone/phishing DOM, auth-flow arbitration, explainable 0–100 verdict.
- Page-runtime guards: paste/file/permission, ClickFix clipboard, download, scareware.
- **632 unit/redteam/compat tests green**; ESLint/prettier clean; validator clean.
- **Byte-reproducible build**: icons are committed source; zip is deterministic
  (fixed mtimes + sorted + `-X`); release cert is a pure function of source.
- **CI** (`release-verify.yml`): lint → validate:extension → tests → e2e → build →
  certify → artifact-drift gate.
- **E2E** (`tests/e2e/extension.spec.ts`): loads MV3 extension via `channel:"chromium"`;
  2/2 green, wired into CI.

## In progress

- Rebuild + commit the release artifact (drifted from source; rebuilt in working
  tree 2026-07-10, awaiting commit).

## Pending / Backlog

- Store logistics: hosted Privacy Policy URL (page exists, must deploy),
  1280×800 screenshot + 440×280 promo tile (none yet), dev account ($5 + ID),
  data-handling disclosures, broad-permission justification.
- Build-time threat-feed snapshot (thousands of hosts vs. current seed).
- On-device ML phishing classifier (TF.js/ONNX, local).
- Cross-browser (Firefox/Edge) manifests + i18n of warning copy.

## Known gaps & caveats

- Broad `host_permissions` (`http/https://*/*`) + `webRequest` + `tabs` → Web Store
  extended review; needs a tight single-purpose justification.
- Zip determinism verified macOS-local; cross-platform relies on Info-ZIP `zip`
  behaving identically on Linux CI (`-X` strips platform extra fields).
- E2E covers load/runtime smoke + popup render; engine scoring stays in unit tests
  (dynamic `import()` is disallowed inside a running service worker).
