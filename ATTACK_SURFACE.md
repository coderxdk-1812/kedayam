# Attack Surface

Inventory of every untrusted input, browser API, and trust boundary the
extension touches. Used to scope adversarial tests and security review.

## Untrusted inputs

| # | Source                              | Sanitizer / guard                                |
|---|-------------------------------------|--------------------------------------------------|
| 1 | Page HTML / DOM                     | `safeDom` (frozen native refs), bounded scans    |
| 2 | Form metadata (action, names)       | `boundedString`, `safeMatchAll`                  |
| 3 | Pasted / dropped data               | `sensitiveDataEngine` (size capped, redacted)    |
| 4 | URL parsed from navigation events   | `URL` constructor in `try/catch`                 |
| 5 | Cross-context messages              | `bus` nonce + `assertEnvelope`                   |
| 6 | Stored settings (chrome.storage)    | `featureFlags.migrate` + schema version          |
| 7 | Optional Safe Browsing / VT replies | Response shape validated, errors swallowed       |
| 8 | Managed-storage policy (enterprise) | Schema validated; unknown keys ignored           |

## Browser APIs used

| API                              | Read / Write | Notes                                  |
|----------------------------------|--------------|----------------------------------------|
| `chrome.tabs.query`              | Read         | Re-injection on install                |
| `chrome.tabs.get`                | Read         | URL for active tab in popup            |
| `chrome.webNavigation.*`         | Read         | Navigation start / commit / redirect   |
| `chrome.webRequest.onBeforeRedirect` | Read     | Observe redirect chain (no blocking)   |
| `chrome.storage.local`           | R/W          | Settings, cache, activity              |
| `chrome.storage.managed`         | Read         | Optional enterprise policy             |
| `chrome.alarms`                  | R/W          | 1-minute heartbeat                     |
| `chrome.notifications`           | Write        | High-confidence dangerous verdicts     |
| `chrome.runtime.onMessage`       | Read         | Envelope-validated                     |
| `chrome.scripting.executeScript` | Write        | Re-inject content on existing tabs     |

Not used: `cookies`, `history`, `bookmarks`, `downloads`, `proxy`,
`nativeMessaging`, `management`, `debugger`, `webRequestBlocking`,
`declarativeNetRequest`, `geolocation`, `clipboardWrite`.

## Privileged operations

| Operation                          | Caller             | Guard                                   |
|------------------------------------|--------------------|-----------------------------------------|
| Inject content script              | background SW      | `isInjectableUrl()`                     |
| Show OS notification               | background SW      | Confidence ≥ 0.8 + cooldown             |
| Persist settings                   | options page       | Schema migration on read                |
| Fetch Safe Browsing                | background SW      | Only if user key present                |
| Fetch VirusTotal                   | background SW      | Only if user key present and flag on    |
| Run sensitive-data scan            | content script     | Bounded input size; in-memory only      |

## Trust boundaries

```text
[ Web page (hostile) ] --isolated world--> [ Content script ]
[ Content script    ] --runtime msg-----> [ Background SW  ]
[ Background SW     ] --(opt) HTTPS-----> [ Safe Browsing / VT ]
[ User              ] --options UI------> [ chrome.storage.local ]
[ Enterprise admin  ] --managed policy--> [ chrome.storage.managed ]
```

Every cross-boundary message is validated by `bus.isValidEnvelope` and
`selfProtection.assertEnvelope`. The page never observes background
state; the content script exposes no callable globals on `window`.

## Known limitations

- Detection is best-effort; novel phishing kits may evade until a
  fixture is added.
- We cannot inspect content of cross-origin iframes; we flag their
  presence on credential pages instead.
- If the user pastes an API key into a textarea before navigating, we
  cannot retroactively warn — we hook at paste/drop/submit time only.

## Suggested adversary scenarios for review

1. Hostile page mutates `window.fetch` / `Document.prototype.querySelector`
   before document_start — `safeDom` should be unaffected.
2. Hostile page floods the mutation observer with 10k nodes — token
   bucket should drop work, not hang.
3. Hostile postMessage with `__proto__` payload — `assertEnvelope`
   should reject.
4. Storage rollback via stale `schemaVersion` — `migrate` must repair.
5. User installs a managed policy with unknown keys — extension should
   ignore unknown keys without crash.
