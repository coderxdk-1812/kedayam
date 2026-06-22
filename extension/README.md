# Kedayam — Browser Shield

**Kedayam** ("shield") is a Manifest V3 browser extension that delivers real-time
phishing prevention, sensitive-data leak protection, and browser-level threat
intelligence. Privacy-first by design — sensitive scanning never leaves your device.

## Capabilities

- **Trust Engine** — aggregates HTTPS, lookalike, redirect, domain-shape,
  freeware threat-blocklist, and (optional) Google Safe Browsing + VirusTotal
  signals into an explainable 0–100 trust score (Safe / Suspicious / Dangerous).
- **Freeware threat blocklist** — a bundled, offline list of known phishing /
  malware hosts ships inside the extension, so reputation protection works with
  **zero API keys and zero network calls** out of the box. An _opt-in_ refresh
  can layer thousands more entries from FREE public feeds (URLhaus, Phishing
  Army, OpenPhish) — only the feed files are fetched; your browsing is never
  sent anywhere.
- **ClickFix / FakeCaptcha guard** — stops the dominant 2024-2025 malware lure:
  pages that silently copy a PowerShell / `mshta` / `curl | bash` command to
  your clipboard and tell you to paste it into the Run dialog or a terminal.
  Kedayam inspects what a page writes to your clipboard locally and blocks with
  a clear warning before you can run it.
- **Malicious-download guard** — warns before an executable download
  (`.exe/.scr/.msi/.hta/.bat/.apk/.dmg/…`) on a low-trust page.
- **URL reputation** — flags high-abuse / free TLDs (`.tk/.ml/.zip/.xyz/…`),
  URL shorteners, and the "brand-domain-as-subdomain" trick
  (`paypal.com.account-verify.tk`) that fools users reading left-to-right.
- **Lookalike & homoglyph detection** — Levenshtein + Unicode mapping against a
  protected-brand list (banks, payments, big-tech, crypto).
- **Local sensitive-data detection** — emails, phones (IN/US), Aadhaar, PAN,
  SSN, IBAN, credit cards (Luhn-validated), AWS/GitHub/Slack tokens, JWTs,
  PEM private keys, plus high-entropy generic secrets.
- **Paste guard** — intercepts paste events into inputs and shows a calm,
  blocking modal before secrets land in third-party forms.
- **File upload guard** — scans textual files (≤2 MB) for PII / secrets
  locally before they upload.
- **Permission monitoring** — wraps `getUserMedia` / `geolocation` to warn
  when low-trust pages request sensitive hardware.
- **Session overrides** — "Trust this site for the session" clears on tab close.
- **Modular architecture** — `lib/trustEngine.js`, `lib/detectors.js`,
  `lib/lookalike.js`, `lib/safeBrowsing.js`, `lib/storage.js` are independent
  and unit-testable.

## Install (unpacked)

1. Download and unzip `kedayam.zip`.
2. Open `chrome://extensions` (works in Chrome, Edge, Brave, Arc, Opera).
3. Toggle **Developer mode** in the top-right.
4. Click **Load unpacked** and select the unzipped `extension/` folder.
5. Pin Kedayam to the toolbar.

## Freeware by design — no keys required

Kedayam is **freeware**. Every protection layer works without any paid service
or API key: the trust engine, lookalike/clone detection, sensitive-data guard,
ClickFix guard, download guard, URL reputation, and the **bundled offline
threat blocklist** all run locally.

### Optional extras

- **Free threat feeds (opt-in)** — enable "Auto-update threat feed" in Options
  to refresh the local blocklist from free public sources (URLhaus, Phishing
  Army, OpenPhish). No account or key needed; only the feed files are fetched.
- **Google Safe Browsing / VirusTotal (optional)** — if you happen to have a
  key you can paste it in Options for extra corroboration, but it is **not
  required** and disabled by default.

## Privacy

- No typed text, pasted content, file contents, or passwords ever leave your browser.
- API keys are stored only in `chrome.storage.local` on this device.
- Only the URL is sent to Safe Browsing / VirusTotal endpoints (and only if you provide a key).
- Telemetry is **opt-in** and currently a placeholder; no endpoint is hit by default.

## Folder layout

```
extension/
├── manifest.json
├── background.js          (service worker; orchestrates scans)
├── lib/                   (pure modules — testable)
│   ├── trustEngine.js
│   ├── lookalike.js
│   ├── detectors.js
│   ├── safeBrowsing.js
│   └── storage.js
├── content/
│   ├── content.js         (paste / file / permission guards + overlay)
│   └── overlay.css
├── popup/                 (toolbar popup UI)
└── options/               (full settings dashboard)
```

## Roadmap

- Firefox / Edge dedicated builds
- AI-assisted phishing classification
- Enterprise dashboard (CloudWatch / DynamoDB pipeline already abstracted in code)
- Cloned-asset cross-origin diff in the content script
