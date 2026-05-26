# Threat Model

This document describes adversaries Kedayam defends against, adversaries
that are explicitly out of scope, and the residual risk users should
understand.

## In-scope adversaries

### A1. Generic phishing kit operator
Hosts a credential-harvesting page on a recently registered domain,
optionally impersonating a known brand.

**Defenses.** Lookalike domain detection, brand impersonation rules,
auth-layout fingerprinting, external form-action detection.

### A2. Phishing-as-a-service (PhaaS) author
Ships kits with bot detection, delayed DOM injection, hidden forms,
prototype pollution attempts, CSS evasion (`display:none` toggles), and
iframe-based credential capture.

**Defenses.** `safeDom` freezes native DOM references at document_start;
`scheduler` budgets mutation processing; `cloneDetection` requires
structural + visual corroboration; iframe credential fields are flagged.

### A3. Malicious paste / drop into trusted apps
A user accidentally pastes an API key or PAN into a chat window or
public form.

**Defenses.** `sensitiveDataEngine` intercepts paste/drop/submit events,
classifies the payload locally, and prompts before submission.

### A4. Hostile page targeting the extension
Tries to crash, hang, or exhaust the extension to evade detection: huge
DOM payloads, regex bombs, prototype pollution, message-channel flooding.

**Defenses.** `selfProtection` provides bounded regex/string/array/JSON
primitives; `bus` uses nonce validation and envelope checks; mutation
queue uses a token bucket.

## Out-of-scope adversaries

- **A nation-state attacker with browser zero-days.** No client extension
  defends against arbitrary RCE inside the renderer.
- **Compromised user device (malware, keyloggers).** Kedayam cannot
  protect against an attacker with code execution outside the browser.
- **Server-side attacks against legitimate sites.** Kedayam evaluates
  what the browser actually loads; it cannot detect breaches at trusted
  origins.
- **Malicious browser extensions running alongside Kedayam.** Extensions
  share permissions models; user must trust their other extensions.

## Trust boundaries

```text
+--------------------+        +---------------------+
| Page (untrusted)   |  msg   | Content script      |
|  DOM, scripts,     |<-----> | (Kedayam, isolated  |
|  paste/drop events |        |  world)             |
+--------------------+        +----------+----------+
                                         |
                                         | chrome.runtime
                                         v
                              +---------------------+
                              | Background SW       |
                              | (trustEngine,       |
                              |  storage, network)  |
                              +----------+----------+
                                         |
                                         | optional (with user key)
                                         v
                              +---------------------+
                              | Safe Browsing / VT  |
                              +---------------------+
```

- Page → content boundary uses isolated worlds (Chrome MV3 default).
- Content → background messages carry a nonce; envelope must validate.
- Background → external network is gated by user-supplied API keys.

## Residual risk

- Detection has a known false-negative rate; the suite targets
  ≥ 90% recall on the included fixtures. Novel kits may slip through
  until fixtures are added.
- False positives are minimized by confidence-band gating, cooldowns,
  and developer-host suppression — but a small rate is unavoidable.
- The local sensitive-data engine cannot inspect data already encrypted
  by the page before paste.

These trade-offs are intentional: Kedayam optimizes for *correctness
without surveillance* over comprehensive coverage.

## A5. Co-installed malicious extension (in-scope, partial)

A second extension installed by the user attempts to poison Kedayam's
safe-domain learner by sending forged `trustForSession` or `saveSettings`
messages over `chrome.runtime`.

**Defenses.** `externally_connectable` is empty in the manifest;
`isTrustedSender` in `extension/lib/messageSchemas.js` rejects any
message whose `sender.id` differs from `chrome.runtime.id`;
trust-mutating types additionally require a tab or extension-UI origin.
This blocks a co-installed extension's background page from silently
inflating trust counters.

**Residual.** A co-installed extension with arbitrary host permissions
can still inject script into the same pages Kedayam observes — at that
point the user's browser is wholly compromised and no in-browser
defense applies. See `PERMISSIONS.md` for the minimal permission set.

## Non-goals

- Detecting novel phishing kits without a fixture-driven update.
- Defending against attackers with code execution outside the renderer.
- Hiding the extension's presence from a determined fingerprinter.
  `use_dynamic_url` makes static probing harder but the content script
  must still be able to mark up the DOM, which is observable in
  principle.
