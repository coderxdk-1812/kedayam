# Kedayam — Browser Shield

**Kedayam** ("shield") is a Manifest V3 browser extension that delivers real-time
phishing prevention, sensitive-data leak protection, and browser-level threat
intelligence. Privacy-first by design — sensitive scanning never leaves your device.

## Capabilities

- **Trust Engine** — aggregates HTTPS, lookalike, redirect, domain-shape, and
  optional Google Safe Browsing + VirusTotal signals into an explainable
  0–100 trust score (Safe / Suspicious / Dangerous).
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

## Optional: external intelligence

Open the extension's options page to plug in API keys:
- **Google Safe Browsing** — [Get a key](https://developers.google.com/safe-browsing/v4/get-started)
- **VirusTotal** — [Get a key](https://www.virustotal.com/gui/my-apikey)

Without keys, Kedayam still operates fully on local heuristics.

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