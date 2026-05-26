# Architecture

Kedayam is a Manifest V3 browser extension organized into three contexts:
content script (isolated world, runs at `document_start`), background
service worker (MV3 module worker), and the popup/options UIs.

## Module map

```text
extension/
├── manifest.json           — MV3 manifest, minimal permissions
├── background.js           — SW: navigation listeners, arbitration, cache
├── content/
│   ├── content.js          — DOM scanning, paste/drop/submit hooks
│   ├── main-world-shim.js  — minimal MAIN-world helper (no eval, no fetch)
│   └── overlay.css         — toast/modal styles
└── lib/
    ├── arbitration.js          — deterministic verdict arbitration
    ├── authLayout.js           — login-page structural fingerprints
    ├── bus.js                  — message-envelope + nonce validation
    ├── cloneDetection.js       — visual + structural clone signals
    ├── detectors.js            — URL-level signals (IP host, userinfo, …)
    ├── diagnostics.js          — local-only debug buffer (OFF by default)
    ├── explanation.js          — structured verdict explanations
    ├── featureFlags.js         — flag registry + schema migrations
    ├── health.js               — error counters
    ├── injection.js            — content-script (re)injection registry
    ├── logger.js               — leveled console logger
    ├── lookalike.js            — IDN / typosquat heuristics
    ├── phishingHeuristics.js   — page-level heuristics
    ├── safeBrowsing.js         — optional GSB/VT clients (user key only)
    ├── safeDom.js              — frozen native DOM references
    ├── scheduler.js            — token-bucket mutation budget
    ├── selfProtection.js       — bounded regex/string/JSON primitives
    ├── sensitiveDataEngine.js  — local PII/secret classifier
    ├── storage.js              — chrome.storage.local wrapper
    ├── trustEngine.js          — end-to-end URL evaluator
    └── uxPolicy.js             — warning cooldowns, presentation policy
```

## Data flow

1. **Navigation.** Background listens to `webNavigation.onBeforeNavigate`
   and tracks redirect chains. On commit, `trustEngine.evaluateUrl()`
   runs and caches the verdict (host-keyed, TTL-bound).
2. **DOM scan.** Content script (`run_at: document_start`) snapshots
   native DOM functions via `safeDom`, then progressively scans on a
   budgeted `MutationObserver`. Form metadata (no values) is sent to
   the background via a nonce-validated envelope.
3. **Arbitration.** `arbitration.js` combines URL signals, phishing
   heuristics, clone detection, and auth-layout matches into a single
   verdict (`safe | suspicious | dangerous`) with a confidence score.
4. **Presentation.** `uxPolicy.presentationFor()` decides between
   silent, toast, and modal. Cooldowns prevent alert fatigue.
5. **Sensitive paste.** Content script intercepts paste/drop/submit,
   passes the value through `sensitiveDataEngine` in memory, and shows
   a redacted warning if findings exceed threshold.

## Determinism

- All thresholds live in named constants (`ARB_CONST`, `UX_POLICY`,
  `SELF_PROTECTION_LIMITS`).
- No learned weights. No remote rule updates.
- Same input ⇒ same verdict, verified by the replay harness.

## Concurrency model

- The background SW is single-threaded; in-flight URL evaluations are
  deduplicated by URL in `inflight` map.
- The content scanner uses one `MutationObserver` with a token-bucket
  budget — under DOM storms, work is dropped rather than queued.
- Message channels use bounded nonce caches (LRU).

## Build

`scripts/release-build.mjs` runs the test suite, validates the manifest,
profiles performance, packages the extension, and writes a SHA-256
checksum. The build is reproducible: same source ⇒ same zip bytes
(given a stable file order, which `package-extension.mjs` enforces).

## Message provenance and isolation

All inter-context messages flow through three gates before reaching a
handler:

1. **Provenance** — `isTrustedSender(sender, chrome.runtime.id, type)`
   in `extension/lib/messageSchemas.js`. Rejects any sender whose
   extension id does not match this build, and requires trust-mutating
   types to originate from a real tab or one of this extension's pages.
2. **Schema** — `validateMessage(msg)`. Deterministic, side-effect-free
   validators per type. Unknown types, malformed payloads, oversized
   payloads, and invalid enum values are rejected here.
3. **Nonce dedupe** — `NonceCache` drops envelope replays.

`externally_connectable` is empty and `onMessageExternal` /
`onConnectExternal` are registered with explicit deny handlers as
defense-in-depth.
