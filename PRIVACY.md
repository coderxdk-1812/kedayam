# Privacy Policy

Kedayam is a **local-only** browser security extension. It does not collect,
transmit, sell, or share personal information.

## Data Kedayam never sends anywhere

- Browsing history
- Page contents (HTML, text, form values)
- Pasted or dropped data
- URLs you visit
- Detection results, verdicts, or scores
- Identifiers, cookies, or device fingerprints

Kedayam contains **no analytics SDK, no telemetry endpoint, and no
background fetch to maintainer-controlled servers**. The bundled code is
auditable; see `scripts/generate-security-report.mjs` for an automated check.

## Data Kedayam stores locally (in `chrome.storage.local`)

- User settings (sensitivity, allowlist, theme preference)
- A bounded cache of trust verdicts keyed by hostname (TTL-bound)
- An activity log of _your own_ recent verdicts (never page content)
- Per-domain trust counters used to learn safe sites

This data never leaves your browser. You can clear it any time from the
extension Options page.

## Clipboard-write (ClickFix) scanning

To stop "ClickFix" malware, Kedayam inspects text that a **web page writes to
your clipboard** (and the visible on-page instructions) to detect smuggled
system commands. This check is **purely in-memory and local**:

- The page already possesses anything it copied — nothing is exfiltrated.
- The clipboard text is classified and discarded; it is **never stored,
  logged, or transmitted**. Only a short, redacted preview is shown in the
  warning modal.

## Optional threat-feed refresh (off by default)

You can enable an **opt-in** refresh of the local blocklist from FREE public
feeds (URLhaus, Phishing Army, OpenPhish). When enabled:

- Kedayam downloads the public feed _files_ only; the request contains no
  information about you or the pages you visit.
- Matching of your actual URL still happens **locally** against the cached
  list. Disable any time in Options. Default install never makes this call.

## Optional third-party lookups

The extension can call **Google Safe Browsing** or **VirusTotal** if and
only if _you_ paste an API key into the Options page. In that case:

- Only the URL hash or URL is sent, scoped to the lookup request.
- The third party's privacy policy then applies to that request.
- Disable by clearing the key in Options.

Both lookups are disabled out-of-the-box. The default install makes zero
outbound network requests.

## Sensitive-data scanning

When you paste, drop, or submit data, Kedayam runs a **purely in-memory**
classifier (regex + entropy + checksum) to warn you before sensitive values
leave the browser. The raw value is **never persisted, logged, or transmitted**.
Findings are redacted (`AKIA••••••`) before being shown.

## Diagnostics (off by default)

A local-only debug buffer is available for developers. It is:

- Off by default and never auto-enabled.
- Held in memory only — wiped on extension restart.
- Redacted: URLs become hostnames, long tokens become `[token]`, emails
  become `[email]`.
- Never written to storage. Never sent over the network.

## Permissions and why

See `PERMISSIONS.md` for a justification of every permission requested.

## Contact

Privacy questions: open an issue on the project repository.

## Trust-learning provenance

Kedayam's "safe-domain" counter (used to raise the trust floor for
domains a user repeatedly marks as safe) can ONLY be incremented by
messages whose sender id matches this extension's `chrome.runtime.id`
and which originate from a tab the user is actively browsing or from
the extension's own UI. A co-installed extension cannot silently
inflate these counters.
