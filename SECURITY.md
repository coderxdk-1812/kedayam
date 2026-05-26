# Security Policy

Kedayam is a local browser security extension. Security issues are taken
seriously and disclosed transparently.

## Supported Versions

Only the latest released version receives security fixes.

## Reporting a Vulnerability

Open a private security advisory on the project's repository, or email the
maintainers with the prefix `[kedayam-security]`. Please include:

- A description of the issue and its impact.
- A minimal reproduction (HTML fixture preferred).
- Affected browser(s) and extension version.
- Your suggested classification (info / low / medium / high / critical).

We aim to acknowledge reports within 5 business days and to ship a fix or
mitigation within 30 days for high/critical issues.

## Scope

In scope:

- Bypass of phishing detection on a representative kit
- Sensitive-data leakage through the extension itself
- Self-protection failures (extension crash, hang, memory blow-up
  triggered by a hostile page)
- Privilege escalation between content/background contexts
- Storage leakage of user content or secrets

Out of scope:

- Missing detections on novel phishing kits (file as a feature request).
- Issues that require the user to disable security features.
- Issues only reproducible in unsupported browsers
  (Chrome < 114, Firefox < 115).

## Guarantees

Kedayam ships with the following non-negotiable guarantees, validated by
the test suite:

1. **No telemetry.** No analytics, beacons, or background pings.
2. **No remote code.** All logic ships in the signed bundle.
3. **No persistence of user content.** Page text, form values, URLs with
   query strings, and detection payloads are never written to disk.
4. **No third-party network calls** unless the user explicitly provides
   an API key for Google Safe Browsing or VirusTotal.
5. **Deterministic scoring.** Same input ⇒ same verdict; thresholds are
   centralized constants, not learned weights.

See `PRIVACY.md`, `THREAT_MODEL.md`, and `ARCHITECTURE.md` for details.

## Extension isolation model (v1.0.0+)

Kedayam is hardened against cross-extension trust poisoning and minimizes
its externally reachable surface:

- `externally_connectable` is **empty** — no web page and no other
  extension can open a runtime channel to Kedayam.
- Every `chrome.runtime.onMessage` is provenance-validated:
  `sender.id` must equal `chrome.runtime.id`, and the message must
  originate either from a real tab (this extension's content script) or
  from one of this extension's own UI pages.
- Trust-mutating messages (`trustForSession`, `saveSettings`,
  `clearCaches`, `logEvent`) carry an additional origin check before the
  safe-domain learner is allowed to bump a counter.
- All inbound messages pass a deterministic schema in
  `extension/lib/messageSchemas.js` — unknown types, malformed payloads,
  oversized payloads, and invalid enum values are rejected before any
  handler runs.

## Web-accessible surface

Only one resource is web-accessible: `content/main-world-shim.js`. It is
the CSP-safe permission-watch shim and must be reachable from the page's
MAIN world. Its URL uses `use_dynamic_url: true` so the
`chrome-extension://<id>/<token>` path rotates per session, removing the
static fingerprint a phishing kit could probe.

`overlay.css` is NOT web-accessible — it ships through
`content_scripts.css` and pages have no reason to read it.
