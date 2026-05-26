# Kedayam Production Hardening — Implementation Roadmap

## Current State Audit

Already in place from prior iterations:
- MV3 manifest with declarative content script + main-world shim via `web_accessible_resources` (no inline scripts) — the CSP issue you cite was already fixed last turn by replacing `textContent` injection with `chrome.runtime.getURL("content/main-world-shim.js")`.
- Trust Engine v2 (weighted, explainable, confidence-aware, categorized signals).
- Lookalike + homoglyph detection, Safe Browsing + VirusTotal connectors with timeouts.
- Safe-domain learning + allowlist trust floor.
- Vitest unit suite (33 passing) + Playwright config.
- Build / package / validate scripts.

Genuine gaps to close:
1. **Injection registry** — content script is declarative-only; no `chrome.scripting` programmatic fallback, no skip-list for `chrome://`, no per-tab dedupe.
2. **Service worker lifecycle** — no heartbeat / alarms keep-alive, no message-version validation, no centralized message bus.
3. **Clone detection** — favicon/asset-origin analysis not yet implemented.
4. **Warning UX tiers** — overlay exists but is single-tier; needs LOW (inline) / MEDIUM (modal) / HIGH (block) escalation.
5. **File upload scanning** — paste scanning exists, file scanning is stub-level.
6. **Performance** — MutationObserver throttling and `requestIdleCallback` scheduling are missing.
7. **Diagnostics** — no structured logger, no health monitor, no crash recovery surface.
8. **Playwright** — only smoke test exists.

## Execution Plan (incremental, validated subsystem-by-subsystem)

### Subsystem A — Injection & Lifecycle (Phase 1, top priority)
- New `extension/lib/injection.js`: tab-aware registry tracking which tabs have content + shim injected, with skip-list for `chrome://`, `edge://`, `about:`, `chrome-extension://`, `view-source:`, `devtools://`, Chrome Web Store.
- `background.js`: on `tabs.onUpdated` (status=loading) call registry; use `chrome.scripting.executeScript` as a fallback when the declarative script didn't fire (e.g. pre-existing tabs after install/update). Clear registry on `tabs.onRemoved`.
- New `extension/lib/bus.js`: typed message bus with `{v:1, type, payload, nonce}` envelope, schema validation, dedupe by nonce, timeout-aware `request()`.
- Service-worker heartbeat via `chrome.alarms` (60s) to refresh caches and prune stale tab state. Reconnect-safe `chrome.runtime.onMessage` wrapper.

### Subsystem B — Diagnostics & Health (Phase 1 cont.)
- `extension/lib/logger.js`: leveled (`debug|info|warn|error`), ring-buffered in `chrome.storage.session`, redaction of secrets/PII before write.
- `extension/lib/health.js`: counters (scans, errors, dropped messages, observer ticks); exposed to popup "Diagnostics" panel.

### Subsystem C — Trust Engine extensions (Phases 2–4)
- Extend `trustEngine.js` with two new categories already scaffolded:
  - **clone**: favicon hash compared against known-brand favicon hashes; cross-origin `<script>`/`<link rel=stylesheet>` whose host ≠ page root and ∉ trusted CDN list (already in `safeBrowsing.js`); brand logo image served from non-brand origin.
  - **permission**: increments when shim posts `kedayam:perm` events; combined with low trust → escalates phishing confidence.
- Add `phishingConfidence` and `cloneConfidence` to result object alongside existing `confidence`.
- Content script collects clone-detection inputs once on `DOMContentLoaded` (idle-callback) and posts to background for evaluation.

### Subsystem D — Warning UX Tiers (Phase 7, 11, 12)
- `content/overlay.css` + new `content/warning.js`: three tiers
  - LOW: top-of-page slim banner, auto-dismiss 8s.
  - MEDIUM: corner card with "Why?" expander, manual dismiss.
  - HIGH: full-viewport blocking modal with explainability list, "Leave" (default) and "Proceed for this session" override.
- Tier chosen by status × confidence (e.g. dangerous + conf>0.7 → HIGH).
- Popup redesign: compact card stack — Trust / Confidence / Phishing / Clone scores, Why-this-score list, recent detections, override state, diagnostics link.

### Subsystem E — Sensitive Data + File Scanning (Phases 5–6)
- Refine `detectors.js` with contextual field awareness (look at nearest `<label>`, `name`, `autocomplete`).
- Local file scanning: `pdfjs-dist` (lazy-loaded via `import()`), `mammoth` for DOCX, native `TextDecoder` for CSV/TXT/JSON. All in-memory, no network. Hooked from `input[type=file]` `change` events.

### Subsystem F — Performance (Phase 10)
- `extension/lib/scheduler.js`: `idle()`, `debounce()`, `throttle()`, `budget()` (cap N scans/sec).
- Wrap MutationObserver in scheduler; downgrade observer when domain is "learned safe".

### Subsystem G — Tests (Phase 13)
- Add Vitest tests for: injection skip-list, bus envelope validation, clone-detection scoring, scheduler budget, warning tier selection.
- Add Playwright fixtures: synthetic phishing page (paypa1.com-style), fake banking clone (cross-origin assets), redirect-chain page, paste/file simulation, SPA navigation. Run via `serve` of a `tests/fixtures/` folder.

### Subsystem H — Build Validation (Phase 14)
- Extend `scripts/validate-extension.mjs`: assert no inline `<script>` strings outside fixtures, manifest matches `web_accessible_resources` against actual files, every icon size present, MV3 schema check, CSP self-check.

### Validation gates
After each subsystem: `bun test` (unit) → `bun run build:extension` (validate+package) → spot-check `tests/e2e` where relevant. Stop and report if anything regresses before moving on.

## Out of Scope (intentional)
- No rewrite of dashboard/website beyond minor copy if needed.
- No external telemetry endpoint — diagnostics stay local (privacy-first).
- No new persistent storage of user content.

## Deliverable per turn
Given the size, I'll execute one or two subsystems per turn, run tests, and report what passed/failed before continuing — rather than a single monster commit that's hard to review or roll back.
