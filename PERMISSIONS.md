# Permission Justifications

Kedayam requests the minimum permissions required to deliver real-time
phishing protection. Each permission and host scope below is justified
for browser-store reviewers.

## `permissions`

| Permission      | Why Kedayam needs it                                                                                     | Alternatives considered                                         |
| --------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `activeTab`     | Read the current tab URL to show the trust verdict in popup.                                             | Required; no alternative.                                       |
| `alarms`        | 1-minute heartbeat to prune stale per-tab state.                                                         | `setInterval` unavailable in MV3 SW.                            |
| `storage`       | Persist user settings, allowlist, and bounded verdict cache.                                             | `chrome.storage.session` lacks persistence across restarts.     |
| `tabs`          | Resolve tab IDs to URLs for re-injection on install/upgrade.                                             | Required by MV3 re-inject pattern.                              |
| `notifications` | Surface "dangerous site blocked" alerts when the user's tab is not focused.                              | Without this, user only sees in-page toast which can be hidden. |
| `webNavigation` | Detect navigation start, redirects, and commit to evaluate the destination _before_ page load completes. | Content scripts run too late to warn pre-render.                |
| `webRequest`    | Observe redirect chains (read-only; no `blocking`, no modification).                                     | `webNavigation` alone misses sub-redirect details.              |

We do NOT request: `webRequestBlocking`, `declarativeNetRequest`,
`cookies`, `history`, `bookmarks`, `downloads`, `proxy`, `nativeMessaging`,
`management`, `debugger`, `<all_urls>` in content script `js` (we use
`matches: ["<all_urls>"]` for scripting only, and the script does not
exfiltrate page content).

## `host_permissions`: `http://*/*`, `https://*/*`

Phishing protection requires the extension to evaluate every site the
user navigates to. Narrower host patterns would silently disable
protection on the sites that matter (e.g. newly registered domains).

The extension's network use of these hosts is restricted to:

1. Reading the URL the user is already navigating to.
2. Optional Safe Browsing / VirusTotal lookups, only if the user
   supplied an API key in Options.
3. Optional threat-feed refresh (off by default): downloading FREE public
   blocklist files (URLhaus / Phishing Army / OpenPhish) when the user
   enables auto-update. The request carries no user or browsing data.

No host content is fetched, scraped, or transmitted by Kedayam itself.

## New freeware protection layers require NO new permissions

The threat blocklist, ClickFix clipboard guard, malicious-download guard, and
URL-reputation heuristics were added without requesting any additional
permission. The ClickFix guard observes clipboard writes via the existing
MAIN-world shim (in-page, local); the download guard uses ordinary DOM click
handling; the blocklist matches locally against bundled data. No
`clipboardRead`, `clipboardWrite`, `downloads`, or `declarativeNetRequest`
permission is requested.

## `web_accessible_resources`

Only the overlay CSS and the main-world shim are exposed. The shim
contains no `eval`, no `Function(...)`, no `fetch`, and no message
posting back to the page — it is a passive helper.

## Remote code policy

Kedayam ships zero remote code. No `script` tags load external JS, no
`import()` from URLs, no eval-based loaders, no rule packs fetched from
the network. All detection logic is in the signed bundle and frozen at
load time.
