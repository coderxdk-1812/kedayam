# Changelog

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
