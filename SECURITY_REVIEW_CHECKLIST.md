# Security Review Checklist

Reviewer: _________________  Date: __________  Version reviewed: __________

## Privacy guarantees

- [ ] No telemetry endpoints in source (`rg -n "analytics|beacon"`)
- [ ] No remote code execution (`rg -n "eval\\(|new Function"`)
- [ ] No `chrome.storage.sync` (only `.local`)
- [ ] No background fetch on idle (DevTools Network tab, 5 min idle)
- [ ] Sensitive-data findings never include raw secrets
- [ ] Diagnostics buffer disabled by default
- [ ] Page text / form values never stored in chrome.storage

## Permissions

- [ ] Each `permissions` entry justified in `PERMISSIONS.md`
- [ ] No `<all_urls>` in `web_accessible_resources` beyond shim + CSS
- [ ] No `webRequestBlocking`, `cookies`, `history`, `debugger`
- [ ] Content script does not exfiltrate page content

## Determinism

- [ ] Same input ⇒ same verdict (run replay harness twice, diff)
- [ ] All thresholds are named constants (no magic numbers in hot paths)
- [ ] No learned weights, no remote rule updates
- [ ] Migration is pure and idempotent (`featureFlags.test.js`)

## Self-protection

- [ ] Bounded regex / string / JSON primitives in use
- [ ] Message envelopes nonce-validated
- [ ] Native DOM references frozen at document_start
- [ ] Mutation observer budgeted (token bucket)

## UX & accessibility

- [ ] Warnings calm, technical, non-alarmist
- [ ] Cooldowns prevent alert fatigue
- [ ] Reduced-motion respected
- [ ] Colorblind-safe shape cues present (not color-only)
- [ ] Keyboard focus visible

## Adversarial resilience

- [ ] `tests/redteam/*` all pass
- [ ] `tests/fuzz/*` all pass; no timeouts
- [ ] `tests/stability/*` complete under bounded memory

## Documentation

- [ ] `SECURITY.md`, `PRIVACY.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`,
      `PERMISSIONS.md`, `ATTACK_SURFACE.md`, `AUDIT_GUIDE.md` all current
- [ ] Architecture diagrams match the code

## Sign-off

- [ ] No high or critical findings open
- [ ] Reviewer recommends release
- [ ] Date / signature: __________________________
