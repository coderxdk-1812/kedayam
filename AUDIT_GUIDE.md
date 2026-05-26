# Audit Guide

This guide helps an independent reviewer verify Kedayam's security and
privacy claims in roughly two to four hours of focused work.

## 1. Trust the build, then trust the source

```bash
# Reproduce the release zip and checksum
node scripts/release-build.mjs
node scripts/release-certify.mjs
sha256sum public/kedayam.zip
diff -q <(cut -d' ' -f1 public/kedayam.zip.sha256) <(sha256sum public/kedayam.zip | cut -d' ' -f1)
```

The certification JSON (`public/kedayam-release-cert.json`) is the
ground-truth machine summary. Expect `releaseCandidate: true`,
`telemetry: false`, `remoteExecution: false`.

## 2. Verify the privacy claims

```bash
rg -n "eval\\(|new Function\\(|sendBeacon|navigator\\.connect" extension/
rg -n "fetch\\(|XMLHttpRequest" extension/lib/  # only safeBrowsing.js, gated by user key
rg -n "chrome\\.storage" extension/             # storage.local only — no .sync
```

Confirm no analytics SDKs, no cloud endpoints, no remote rule packs.

## 3. Walk the data path

Read in this order:

1. `extension/manifest.json` — every permission justified in `PERMISSIONS.md`.
2. `extension/background.js` — entry points for navigation events.
3. `extension/lib/trustEngine.js` — verdict pipeline.
4. `extension/lib/arbitration.js` — deterministic combiner.
5. `extension/content/content.js` — DOM scanning, paste/drop hooks.
6. `extension/lib/sensitiveDataEngine.js` — local PII/secret classifier.

The diagrams in `docs/diagrams/` mirror these modules.

## 4. Run the test corpus

```bash
bunx vitest run                       # 220+ tests, all categories
bunx vitest run tests/unit/privacyGuarantees.test.js
bunx vitest run tests/unit/phishingReplay.test.js
bunx vitest run tests/redteam/
bunx vitest run tests/fuzz/
bunx vitest run tests/stability/
```

## 5. Audit the rule registry

Open `extension/lib/rules/index.js`. Each rule is a pure function with:

- a stable `id`
- declared `severity`
- pure `evaluate(context)` returning `{ matched, contribution, explain }`

Reviewers can replay any rule against any fixture without booting a browser.

## 6. Inspect the safelist

`extension/lib/safelist.js` is a static, versioned list of well-known
identity, banking, and password-manager roots. There is no remote
update channel. Diffs to this file should appear in version control.

## 7. Failure-mode walkthrough

- Disable network — extension MUST still load and run (Safe Browsing
  silently no-ops without a user API key).
- Visit `chrome://extensions` and inspect service worker — no
  background fetch on idle.
- Open Options → Diagnostics — should be OFF; toggle, then reload to
  confirm persistence is in-memory only.

## 8. Reporting findings

Use the `SECURITY_REVIEW_CHECKLIST.md` template, then file findings
via the disclosure process in `SECURITY.md`.
