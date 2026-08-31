/* Kedayam content script — runs in isolated world.
 * - Listens for trust verdicts from the background and shows a calm toast.
 * - Intercepts paste events and warns if sensitive data is detected.
 * - Scans selected files for likely PII / secrets before they upload.
 * - Watches sensitive permission requests (camera/mic/location/clipboard).
 * Nothing scanned ever leaves the page.
 */
(() => {
  if (window.__kedayamLoaded) return;
  window.__kedayamLoaded = true;

  // Safe defaults so listeners work even before chrome.runtime replies.
  const DEFAULT_SETTINGS = {
    enabled: true,
    detection: {
      sensitivity: "balanced",
      regions: { india: true, us: true, eu: true, global: true },
      fileScanning: true,
      pasteInterception: true,
      permissionMonitoring: true,
      redirectAnalysis: true,
      cloneDetection: true,
      localBlocklist: true,
      clickFixGuard: true,
      downloadGuard: true,
      urlReputation: true,
      scarewareGuard: true,
      threatFeedAutoUpdate: false,
    },
  };
  const STATE = { settings: DEFAULT_SETTINGS, lastResult: null, settingsLoaded: false };
  const sessionTrusted = new Set();
  // Domains the user permanently trusted (settings.allowlist, root domains).
  // Mirrored locally so the page stops surfacing trust modals immediately,
  // before the background's re-scan verdict arrives.
  const permanentTrusted = new Set();

  // True when the current host sits under a root the user has permanently
  // trusted (exact root or any subdomain of it).
  function isPermanentlyTrusted(host = location.hostname) {
    const h = String(host || "").toLowerCase();
    const roots = [...permanentTrusted, ...(STATE.settings?.allowlist || [])];
    return roots.some((r) => {
      const root = String(r || "")
        .toLowerCase()
        .replace(/^\*?\.?/, "");
      return !!root && (h === root || h.endsWith(`.${root}`));
    });
  }

  // Ask the background to add this page's registrable root to the user
  // allowlist. The content script never derives the root itself — it only
  // reports its own hostname, and the background does the public-suffix work.
  function trustPermanently() {
    permanentTrusted.add(location.hostname);
    sessionTrusted.add(location.hostname);
    try {
      chrome.runtime.sendMessage({ type: "trustPermanent", domain: location.hostname }, (res) => {
        void chrome.runtime.lastError;
        if (res?.root) permanentTrusted.add(res.root);
      });
    } catch {}
  }

  // VirusTotal lookup for the current site. Only the origin is handed over —
  // never the path or query string, which can carry session tokens or PII.
  function virusTotalUrl(href = location.href) {
    try {
      const u = new URL(href);
      return `https://www.virustotal.com/gui/search?query=${encodeURIComponent(`${u.origin}/`)}`;
    } catch {
      return null;
    }
  }
  const DEV = !chrome.runtime.getManifest?.().update_url;
  const debug = (...args) => {
    if (DEV) console.info("[Kedayam]", ...args);
  };

  // ---------- Ephemeral replay store (Issue NEW-01) ----------
  // Inlined mirror of lib/ephemeralReplay.js (content scripts are not modules).
  // Holds the intercepted paste payload during the confirmation modal so the
  // extension never has to re-read the clipboard — which would require an
  // extra permission and silently fail when denied.
  const ephemeralReplay = (() => {
    const TTL = 60 * 1000;
    const MAX = 8;
    const store = new Map();
    let counter = 0;
    function evict() {
      while (store.size > MAX) {
        const first = store.keys().next().value;
        if (first == null) break;
        zeroize(first);
      }
    }
    function storeFn(payload) {
      if (typeof payload !== "string" || !payload.length) return null;
      const tok = `kr_${++counter}_${Math.random().toString(36).slice(2, 10)}`;
      const e = { payload, expires: Date.now() + TTL, timer: null };
      try {
        e.timer = setTimeout(() => zeroize(tok), TTL);
      } catch {}
      store.set(tok, e);
      evict();
      return tok;
    }
    function consume(tok) {
      const e = tok && store.get(tok);
      if (!e) return null;
      const v = e.expires < Date.now() ? null : e.payload;
      zeroize(tok);
      return v;
    }
    function zeroize(tok) {
      const e = store.get(tok);
      if (!e) return;
      try {
        if (e.timer) clearTimeout(e.timer);
      } catch {}
      e.payload = "";
      e.timer = null;
      store.delete(tok);
    }
    return { store: storeFn, consume, zeroize, _size: () => store.size };
  })();

  // ---------- Local detectors (mirror of lib/sensitiveDataEngine.js) ----------
  // Ephemeral, in-memory scanner. NO raw value is ever persisted, transmitted,
  // or returned upstream — findings carry redacted previews only.
  const PATTERNS = [
    {
      id: "email",
      label: "Email address",
      sev: "low",
      region: "global",
      re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
      conf: 0.7,
    },
    {
      id: "phoneIN",
      label: "Indian phone number",
      sev: "medium",
      region: "india",
      re: /(?:\+?91[\s-]?)?[6-9]\d{9}\b/g,
      conf: 0.7,
    },
    {
      id: "phoneUS",
      label: "US phone number",
      sev: "medium",
      region: "us",
      re: /\b(?:\+?1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
      conf: 0.7,
    },
    {
      id: "aadhaar",
      label: "Aadhaar",
      sev: "critical",
      region: "india",
      re: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      conf: 0.9,
    },
    {
      id: "pan",
      label: "PAN",
      sev: "high",
      region: "india",
      re: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
      conf: 0.9,
    },
    {
      id: "ssn",
      label: "US SSN",
      sev: "critical",
      region: "us",
      re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
      conf: 0.95,
    },
    {
      id: "iban",
      label: "IBAN",
      sev: "high",
      region: "eu",
      re: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g,
      conf: 0.85,
    },
    {
      id: "card",
      label: "Credit card",
      sev: "critical",
      region: "global",
      re: /\b(?:\d[ -]*?){13,19}\b/g,
      validate: (s) => luhn(s.replace(/\D/g, "")),
      conf: 0.92,
    },
    {
      id: "aws",
      label: "AWS access key",
      sev: "critical",
      region: "global",
      re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
      conf: 0.98,
    },
    {
      id: "gh",
      label: "GitHub token",
      sev: "critical",
      region: "global",
      re: /\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/g,
      conf: 0.99,
    },
    {
      id: "slack",
      label: "Slack token",
      sev: "critical",
      region: "global",
      re: /\bxox[abps]-[A-Za-z0-9-]{10,}\b/g,
      conf: 0.97,
    },
    {
      id: "stripe",
      label: "Stripe key",
      sev: "critical",
      region: "global",
      re: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{24,}\b/g,
      conf: 0.99,
    },
    {
      id: "openai",
      label: "OpenAI / LLM key",
      sev: "critical",
      region: "global",
      re: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}\b/g,
      conf: 0.95,
    },
    {
      id: "gcp",
      label: "Google Cloud API key",
      sev: "critical",
      region: "global",
      re: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
      conf: 0.97,
    },
    {
      id: "jwt",
      label: "JWT",
      sev: "high",
      region: "global",
      re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      conf: 0.9,
    },
    {
      id: "pk",
      label: "Private key",
      sev: "critical",
      region: "global",
      re: /-----BEGIN ((RSA|EC|OPENSSH|PGP) )?PRIVATE KEY-----/g,
      conf: 1,
    },
  ];

  // Documentation / dev / example contexts where matches should be suppressed.
  const PLACEHOLDER_TOKENS = [
    "your_",
    "<your",
    "example",
    "placeholder",
    "xxxxxxxx",
    "lorem",
    "ipsum",
    "abc123",
    "password123",
    "changeme",
    "demo_",
    "sample_",
    "fake_",
    "test_only",
    "dotenv",
    "process.env.",
    "sk_test_",
  ];
  const DOC_CONTEXT =
    /\b(curl\s+-X|fetch\(|axios\.|require\(|import\s+\{|getenv|process\.env|export\s+(const|let|var)|api\s+reference|see\s+docs|getting started|tutorial)\b/i;
  // Hosts where we silence warnings — developer tools, docs, internal envs.
  const DEV_SUPPRESS_HOSTS =
    /(^|\.)(github\.com|gitlab\.com|stackoverflow\.com|stackexchange\.com|developer\.mozilla\.org|docs\.|developer\.|api\.|swagger\.|postman\.com|notion\.so|localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?$/i;
  function isDevHost() {
    try {
      return DEV_SUPPRESS_HOSTS.test(location.hostname);
    } catch {
      return false;
    }
  }

  function luhn(num) {
    if (!/^\d+$/.test(num) || num.length < 13 || num.length > 19) return false;
    let s = 0,
      alt = false;
    for (let i = num.length - 1; i >= 0; i--) {
      let n = +num[i];
      if (alt) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      s += n;
      alt = !alt;
    }
    return s % 10 === 0;
  }
  function entropy(s) {
    const f = Object.create(null);
    for (const c of s) f[c] = (f[c] || 0) + 1;
    let H = 0;
    for (const c in f) {
      const p = f[c] / s.length;
      H -= p * Math.log2(p);
    }
    return H;
  }
  function sliceWindow(text, offset, len) {
    return text
      .slice(Math.max(0, offset - 80), Math.min(text.length, offset + len + 80))
      .toLowerCase();
  }
  function hasPlaceholderToken(win) {
    const lower = win.toLowerCase();
    return PLACEHOLDER_TOKENS.some((t) => lower.includes(t));
  }
  function looksLikeMockNumber(s) {
    const d = s.replace(/\D/g, "");
    if (!d) return false;
    if (/^(\d)\1+$/.test(d)) return true;
    if (/^4242424242424242$/.test(d)) return true;
    if (/^(0123456789|1234567890)/.test(d)) return true;
    return false;
  }
  // scan returns ONLY redacted previews + structural metadata. The raw text
  // argument MUST be discarded by the caller immediately after this returns.
  function scan(text) {
    if (!text || typeof text !== "string" || text.length > 200000) return [];
    const regions = STATE.settings?.detection?.regions || {
      india: true,
      us: true,
      eu: true,
      global: true,
    };
    const docCtx = DOC_CONTEXT.test(text);
    const out = [];
    for (const p of PATTERNS) {
      if (p.region !== "global" && !regions[p.region]) continue;
      p.re.lastIndex = 0;
      let m,
        count = 0;
      while ((m = p.re.exec(text)) && count < 25) {
        count++;
        const raw = m[0];
        const win = sliceWindow(text, m.index, raw.length);
        if (p.validate && !p.validate(raw)) continue;
        if (hasPlaceholderToken(win)) continue;
        if (looksLikeMockNumber(raw) && p.id === "card") continue;
        let conf = p.conf || 0.8;
        if (docCtx && p.sev !== "critical") {
          conf *= 0.6;
          if (conf < 0.5) continue;
        }
        out.push({
          kind: p.id,
          label: p.label,
          severity: p.sev,
          confidence: conf,
          value: redact(raw),
        });
        if (out.length > 30) return dedupe(out);
      }
    }
    // Entropy-only fallback: low confidence — never warns alone, requires
    // corroboration (see decideAction).
    for (const tok of (text.match(/[A-Za-z0-9+/_=-]{32,}/g) || []).slice(0, 40)) {
      if (entropy(tok) < 4.5) continue;
      if (hasPlaceholderToken(tok)) continue;
      out.push({
        kind: "entropy",
        label: "High-entropy blob",
        severity: "low",
        confidence: 0.5,
        value: redact(tok),
      });
    }
    return dedupe(out);
  }
  function redact(v) {
    if (v.length <= 6) return "•".repeat(v.length);
    return v.slice(0, 2) + "•".repeat(Math.min(v.length - 4, 10)) + v.slice(-2);
  }
  function dedupe(a) {
    const s = new Set();
    return a.filter((f) => {
      const k = f.kind + ":" + f.value;
      if (s.has(k)) return false;
      s.add(k);
      return true;
    });
  }
  function topSev(findings) {
    const o = { critical: 4, high: 3, medium: 2, low: 1 };
    return findings.reduce((acc, f) => (o[f.severity] > o[acc] ? f.severity : acc), "low");
  }
  // Confidence-band decision: a single weak entropy match never produces a
  // warning. We only warn when at least one validated finding fires, OR when
  // multiple distinct weak signals corroborate each other.
  function decideAction(findings) {
    if (!findings.length) return "ignore";
    if (isDevHost()) return "ignore";
    const strong = findings.filter((f) => f.confidence >= 0.85 && f.kind !== "entropy");
    const validated = findings.filter((f) => f.kind !== "entropy" && f.kind !== "email");
    const sev = topSev(findings);
    if (strong.length) return sev === "critical" || sev === "high" ? "warn" : "toast";
    if (validated.length >= 1 && sev !== "low") return "toast";
    if (findings.length >= 3 && new Set(findings.map((f) => f.kind)).size >= 2) return "toast";
    return "ignore";
  }
  // Expose detection internals ONLY in dev builds (unpacked / no update_url).
  // In production this global is intentionally absent so phishing pages cannot
  // introspect signatures, thresholds, or arbitration internals. Tests import
  // the relevant pure modules directly and do not depend on window globals.
  if (DEV) {
    try {
      window.__kedayam = Object.freeze({ scan, decideAction });
    } catch {}
  }

  // ---------- Overlay root ----------
  function root() {
    let el = document.getElementById("kedayam-root");
    if (!el) {
      el = document.createElement("div");
      el.id = "kedayam-root";
      (document.documentElement || document.body).appendChild(el);
    }
    return el;
  }

  function showToast(result) {
    const r = root();
    let toast = r.querySelector(".ked-toast");
    if (toast) toast.remove();
    toast = document.createElement("div");
    toast.className = "ked-toast";
    toast.dataset.severity = result.status || result.severity || "safe";
    toast.innerHTML = `
      <span class="ked-toast-dot"></span>
      <div>
        <div style="font-weight:600">${escapeHtml(result.title || `Kedayam · trust score ${result.score}/100`)}</div>
        <div class="ked-tiny">${escapeHtml(result.host || result.body || "")}</div>
      </div>`;
    r.appendChild(toast);
    setTimeout(() => toast?.remove(), result.status === "safe" ? 2200 : 5200);
  }

  // Navigate the tab away from a dangerous page. Prefer stepping back to
  // wherever the user came from; if this is the first entry in the tab's
  // history (opened straight from a link in mail/chat), replace it with a
  // blank page so the hostile content is gone either way. Runs in the page's
  // own window via the shared location/history, so it actually unloads.
  function leaveToSafety() {
    try {
      if (window.history.length > 1) {
        window.history.back();
        // If back() didn't unload quickly (pushState/SPA history traps), fall
        // back to a hard replace so "Leave" is never a dead button.
        setTimeout(() => {
          try {
            window.location.replace("about:blank");
          } catch {}
        }, 500);
      } else {
        window.location.replace("about:blank");
      }
    } catch {}
  }

  function showWarningModal({
    title,
    body,
    severity,
    items,
    onContinue,
    onTrust,
    onAlwaysTrust,
    onClearClipboard,
    onLeave,
    verifyUrl,
  }) {
    return new Promise((resolve) => {
      const r = root();
      const old = r.querySelector(".ked-backdrop");
      old?.remove();
      const backdrop = document.createElement("div");
      backdrop.className = "ked-backdrop";
      backdrop.innerHTML = `
        <div class="ked-modal" data-severity="${severity}" role="alertdialog" aria-modal="true" aria-labelledby="ked-title">
          <div class="ked-eyebrow"><span class="ked-dot"></span><span>Kedayam · ${severity} risk</span></div>
          <h2 id="ked-title">${escapeHtml(title)}</h2>
          <p>${escapeHtml(body)}</p>
          ${
            items?.length
              ? `<div class="ked-list">${items
                  .map(
                    (i) => `
            <div class="ked-item"><span>${escapeHtml(i.label)}</span><small>${escapeHtml(i.value || "")}</small></div>
          `,
                  )
                  .join("")}</div>`
              : ""
          }
          ${
            verifyUrl
              ? `<a class="ked-verify-btn" href="${escapeHtml(verifyUrl)}" target="_blank" rel="noopener noreferrer external">🔎 Check this domain on VirusTotal</a>
                 <div class="ked-tiny ked-verify-note">Opens virustotal.com in a new tab with this site's address only — never the page path or anything you typed.</div>`
              : ""
          }
          <div class="ked-actions">
            ${
              onLeave
                ? `<button class="ked-btn-danger" data-act="leave">Leave this page</button>`
                : `<button class="ked-btn-secondary" data-act="cancel">Go back</button>`
            }
            ${onClearClipboard ? `<button class="ked-btn-primary" data-act="clearclip">Clear my clipboard</button>` : ""}
            ${onTrust ? `<button class="ked-btn-secondary" data-act="trust">Trust this site for the session</button>` : ""}
            ${onAlwaysTrust ? `<button class="ked-btn-secondary" data-act="always-trust">Always trust this site</button>` : ""}
            <button class="ked-btn-${severity === "critical" || severity === "high" ? "danger" : "primary"}" data-act="continue">Continue anyway</button>
          </div>
          <div class="ked-tiny">All scanning happens locally on your device. Nothing is uploaded.</div>
        </div>`;
      r.appendChild(backdrop);

      const close = (val) => {
        backdrop.remove();
        document.removeEventListener("keydown", onKey);
        resolve(val);
      };
      const onKey = (e) => {
        if (e.key === "Escape") close("cancel");
      };
      document.addEventListener("keydown", onKey);
      backdrop.addEventListener("click", (e) => {
        // Resolve the action from the nearest [data-act] ancestor so a click on
        // any child node inside a button still registers (robust delegation).
        const target = e.target?.closest?.("[data-act]");
        const act = target?.dataset?.act;
        if (!act) return;
        // Clearing the clipboard needs the user gesture this click provides, so it
        // reliably overwrites the planted command. Keep the modal open + confirm.
        if (act === "clearclip") {
          if (onClearClipboard) onClearClipboard();
          target.textContent = "Clipboard cleared ✓";
          target.disabled = true;
          return;
        }
        if (act === "trust" && onTrust) onTrust();
        // "Always trust" is a persistent decision — confirm it inline so a
        // single mis-click can't permanently silence the scanner.
        if (act === "always-trust" && onAlwaysTrust) {
          if (target.dataset.confirm !== "1") {
            target.dataset.confirm = "1";
            target.textContent = "Click again to confirm";
            return;
          }
          onAlwaysTrust();
        }
        if (act === "continue" && onContinue) onContinue();
        // "Leave this page" actually navigates the tab away from the hostile
        // page — the button is a real escape hatch, not just a dismiss.
        if (act === "leave") {
          close(act);
          if (onLeave) onLeave();
          else leaveToSafety();
          return;
        }
        close(act);
      });
      // Focus the safest default action available.
      (
        backdrop.querySelector("button[data-act='leave']") ||
        backdrop.querySelector("button[data-act='cancel']") ||
        backdrop.querySelector("button[data-act='continue']")
      )?.focus();
    });
  }

  function escapeHtml(s) {
    return String(s).replace(
      /[&<>"']/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
    );
  }

  // ---------- Paste interception ----------
  document.addEventListener(
    "paste",
    (e) => {
      if (!STATE.settings?.detection?.pasteInterception) return;
      const target = e.target;
      if (!target || !(target instanceof Element)) return;
      const tag = target.tagName;
      if (!["INPUT", "TEXTAREA"].includes(tag) && !target.isContentEditable) return;
      let text = e.clipboardData?.getData("text/plain") || "";
      if (!text || text.length > 50000) return;
      const findings = scan(text);
      const action = decideAction(findings);
      // SECURITY: drop the raw payload from local scope ASAP — only redacted
      // findings continue from here.
      text = null;
      if (action === "ignore") return;
      if (sessionTrusted.has(location.hostname)) return;
      const sev = topSev(findings);

      if (action === "toast") {
        showToast({
          severity: "safe",
          title: "Kedayam noticed personal data",
          body: `${findings.length} item${findings.length === 1 ? "" : "s"} stayed local.`,
        });
        log({ kind: "paste-allowed", host: location.hostname, count: findings.length });
        return;
      }

      // action === "warn"
      e.preventDefault();
      e.stopPropagation();
      // Issue NEW-01: capture the intercepted payload into the ephemeral
      // replay store BEFORE the modal opens. We do NOT re-read the clipboard
      // at "Continue" time — that requires the "clipboardRead" permission,
      // which the extension does not (and should not) hold globally. The
      // token is single-use, bounded TTL, zeroized on consume / expiry.
      const replayToken = ephemeralReplay.store(text || "");
      text = null;
      showWarningModal({
        severity: sev === "critical" || sev === "high" ? "high" : "medium",
        title: "Sensitive data detected in your paste",
        body: `You're about to paste ${findings.length} item${findings.length === 1 ? "" : "s"} that look like personal or secret information into ${location.hostname}.`,
        items: findings.slice(0, 6),
        onContinue: () => {
          let replayText = ephemeralReplay.consume(replayToken) || "";
          try {
            if (!replayText) {
              // Token expired or already consumed — explain rather than fail
              // silently. User never gets stuck in a "Continue does nothing" loop.
              showToast({
                severity: "safe",
                title: "Paste replay expired",
                body: "Re-copy and try again. Nothing was sent.",
              });
              return;
            }
            if (target.isContentEditable) {
              document.execCommand("insertText", false, replayText);
            } else {
              const start = target.selectionStart ?? target.value.length;
              const end = target.selectionEnd ?? target.value.length;
              target.value = target.value.slice(0, start) + replayText + target.value.slice(end);
              target.dispatchEvent(new Event("input", { bubbles: true }));
              target.dispatchEvent(new Event("change", { bubbles: true }));
            }
          } catch {
          } finally {
            replayText = "";
            log({ kind: "paste-allowed", host: location.hostname, count: findings.length });
          }
        },
        onTrust: () => sessionTrusted.add(location.hostname),
      }).then((act) => {
        // Always zeroize on close (cancel/escape/continue) — defence in depth.
        ephemeralReplay.zeroize(replayToken);
        if (act === "cancel")
          log({ kind: "paste-blocked", host: location.hostname, count: findings.length });
      });
    },
    true,
  );

  // Form submission interception — catches credential-bearing POSTs that
  // skipped the paste path (typed values, password manager autofill).
  document.addEventListener(
    "submit",
    (e) => {
      if (!STATE.settings?.detection?.pasteInterception) return;
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (sessionTrusted.has(location.hostname)) return;
      try {
        let combined = "";
        for (const el of form.elements) {
          if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) continue;
          const t = (el.type || "").toLowerCase();
          if (t === "password" || t === "submit" || t === "button" || t === "hidden") continue;
          if (typeof el.value === "string" && el.value.length < 2000) combined += " " + el.value;
        }
        const findings = scan(combined);
        combined = null;
        const validated = findings.filter(
          (f) => f.confidence >= 0.85 && f.kind !== "entropy" && f.kind !== "email",
        );
        if (!validated.length) return;
        const action = topSev(validated);
        if (action !== "critical" && action !== "high") return;
        // Cross-origin form action raises severity. Same-origin/blank we only toast.
        const actionAttr = form.getAttribute("action") || "";
        let crossOrigin = false;
        try {
          if (actionAttr) {
            const u = new URL(actionAttr, location.href);
            crossOrigin = u.hostname && u.hostname !== location.hostname;
          }
        } catch {}
        if (!crossOrigin) {
          showToast({
            severity: "safe",
            title: "Kedayam reviewed your submission locally",
            body: `${validated.length} sensitive item${validated.length === 1 ? "" : "s"} detected.`,
          });
          return;
        }
        e.preventDefault();
        e.stopPropagation();
        showWarningModal({
          severity: "high",
          title: "This form posts sensitive data to a different domain",
          body: `${location.hostname} is sending what looks like credentials or secrets to a different site. Confirm before submitting.`,
          items: validated.slice(0, 6),
          onContinue: () => {
            try {
              form.submit();
            } catch {}
          },
          onTrust: () => sessionTrusted.add(location.hostname),
        });
      } catch {}
    },
    true,
  );

  // Drag-and-drop into the page — many editors and chat UIs accept dropped
  // text without firing paste.
  document.addEventListener(
    "drop",
    (e) => {
      if (!STATE.settings?.detection?.pasteInterception) return;
      try {
        const txt = e.dataTransfer?.getData("text/plain") || "";
        if (!txt) return;
        const findings = scan(txt);
        const action = decideAction(findings);
        if (action === "warn" || action === "toast") {
          showToast({
            severity: "safe",
            title: "Kedayam reviewed dropped content",
            body: `${findings.length} item${findings.length === 1 ? "" : "s"} scanned locally.`,
          });
          log({ kind: "drop-scan", host: location.hostname, count: findings.length });
        }
      } catch {}
    },
    true,
  );

  // ---------- File upload scanning ----------
  document.addEventListener(
    "change",
    async (e) => {
      if (!STATE.settings?.detection?.fileScanning) return;
      const t = e.target;
      if (!(t instanceof HTMLInputElement) || t.type !== "file" || !t.files?.length) return;
      const concerns = [];
      for (const f of Array.from(t.files).slice(0, 3)) {
        const text = await readFileText(f);
        if (!text) continue;
        const findings = scan(text);
        if (findings.length) concerns.push({ name: f.name, size: f.size, findings });
      }
      if (!concerns.length) return;
      const flat = concerns.flatMap((c) => c.findings);
      const sev = topSev(flat);
      if (sev === "low") {
        showToast({
          severity: "safe",
          title: "Upload reviewed locally",
          body: "Only low-risk patterns were found.",
        });
        log({ kind: "file-scan", host: location.hostname, files: concerns.map((c) => c.name) });
        return;
      }
      await showWarningModal({
        severity: sev === "critical" || sev === "high" ? "high" : "medium",
        title: "This file may contain sensitive information",
        body: `Kedayam scanned ${concerns.length} file${concerns.length === 1 ? "" : "s"} locally and found patterns that look sensitive. Confirm you intend to share this with ${location.hostname}.`,
        items: flat.slice(0, 6),
      });
      log({ kind: "file-scan", host: location.hostname, files: concerns.map((c) => c.name) });
    },
    true,
  );

  function readFileText(file) {
    const TEXTUAL = /^(text\/|application\/(json|xml|x-yaml|x-sh|javascript|typescript))/i;
    if (file.size > 2 * 1024 * 1024) return Promise.resolve("");
    if (
      !TEXTUAL.test(file.type) &&
      !/\.(txt|csv|json|env|md|log|yml|yaml|sh|js|ts|py|key|pem|pub)$/i.test(file.name)
    ) {
      return Promise.resolve("");
    }
    return new Promise((resolve) => {
      const r = new FileReader();
      r.onload = () => resolve(String(r.result || "").slice(0, 200000));
      r.onerror = () => resolve("");
      r.readAsText(file);
    });
  }

  // ---------- Permission request monitoring ----------
  // Permission monitoring runs in the page's MAIN world (content scripts run
  // in an isolated world, where overriding navigator.* has no effect on the
  // page). We inject a tiny shim and listen for events posted back.
  injectMainWorldShim();
  window.addEventListener("kedayam:perm", (e) => {
    maybeWarnPermission(e.detail || {});
  });

  // ---------- ClickFix / FakeCaptcha clipboard-injection guard ----------
  // Inline mirror of lib/clipboardGuard.js (content scripts are not modules).
  // Detects the dominant 2024-2025 malware lure: a page silently copies an OS
  // command to the clipboard and instructs the victim to paste+run it.
  const CLIP_CMD = [
    { id: "powershell", re: /\b(powershell|pwsh)\b/i, label: "PowerShell" },
    {
      id: "ps-encoded",
      re: /-e(nc|ncodedcommand)?\b\s+[A-Za-z0-9+/=]{12,}/i,
      label: "encoded PowerShell command",
    },
    {
      id: "ps-iex",
      re: /\b(iex|invoke-expression|invoke-webrequest|invoke-restmethod|iwr|irm|downloadstring|downloadfile|frombase64string|start-bitstransfer|net\.webclient)\b/i,
      label: "PowerShell download-and-run",
    },
    {
      id: "ps-hidden",
      re: /-(w(indowstyle)?\s+hidden|nop|noprofile|noni|ep\s+bypass|executionpolicy\s+bypass)\b/i,
      label: "hidden PowerShell flags",
    },
    {
      id: "defender-evade",
      re: /\b(add-mppreference|set-mppreference|-exclusionpath|amsiutils|amsiinitfailed)\b/i,
      label: "antivirus-evasion command",
    },
    { id: "cmd", re: /\bcmd(\.exe)?\s*\/(c|k)\b/i, label: "Windows command shell" },
    { id: "mshta", re: /\bmshta(\.exe)?\b|hta:application|\.hta\b/i, label: "mshta script runner" },
    {
      id: "lolbin",
      re: /\b(certutil|bitsadmin|regsvr32|rundll32|wscript|cscript|msiexec|forfiles|installutil|schtasks|conhost|wmic|hh\.exe)\b/i,
      label: "Windows LOLBin",
    },
    {
      id: "nix-oneliner",
      re: /\b(python3?|node|perl|ruby)\s+-(c|e)\b[^\n]{0,200}(http|socket|urllib|requests|child_process|exec)/i,
      label: "scripting-language download-and-run",
    },
    {
      id: "curl-pipe",
      re: /\b(curl|wget)\b[^\n|]{0,200}\|\s*(ba)?sh\b/i,
      label: "curl/wget piped to a shell",
    },
    {
      id: "curl-iex",
      re: /\b(curl|wget|iwr)\b[^\n|]{0,200}\|\s*iex\b/i,
      label: "download piped to PowerShell",
    },
    {
      id: "base64-sh",
      re: /base64\s+(-d|--decode)\b[^\n|]{0,120}\|\s*(ba)?sh\b/i,
      label: "base64-decoded shell command",
    },
    { id: "osascript", re: /\bosascript\b|\bdo shell script\b/i, label: "macOS osascript" },
  ];
  const CLIP_STRONG = new Set([
    "ps-encoded",
    "ps-iex",
    "ps-hidden",
    "defender-evade",
    "mshta",
    "curl-pipe",
    "curl-iex",
    "base64-sh",
    "lolbin",
    "nix-oneliner",
  ]);
  const RUN_DIALOG = [
    /\bwin(dows)?\s*\+\s*r\b/i,
    /\bpress\s+(the\s+)?(windows|win)\b[^]{0,40}\br\b/i,
    /\b(hold|press)\b[^]{0,40}\bwindows\s*key\b[^]{0,40}\br\b/i,
    /⊞/,
    /\b(open|launch)\s+(the\s+)?(run\s+dialog|run\s+(box|window)|powershell|terminal|command\s+prompt|cmd)\b/i,
    /\bpaste\b[^]{0,40}\b(press|hit)\s+(enter|return)\b/i,
    /\bpaste\s+(this|the\s+(code|command|script)|it)\b/i,
  ];
  const FAKE_VERIFY = [
    /\bverify\s+(you('| a)?re|that you are)\s+(a\s+)?human\b/i,
    /\bi('| a)?m not a robot\b/i,
    /\b(human|robot)\s+verification\b/i,
    /\bcaptcha\b/i,
    /\bchecking\s+(if\s+)?your\s+browser\b/i,
    /\bray\s*id\b/i,
    /\bverification\s+(steps|failed|required|id)\b/i,
  ];

  function classifyClip(text) {
    if (typeof text !== "string" || text.length < 6) return null;
    const s = text.slice(0, 8000);
    const hits = CLIP_CMD.filter((c) => c.re.test(s));
    if (!hits.length) return null;
    const strong = hits.some((h) => CLIP_STRONG.has(h.id));
    const conf = strong
      ? Math.min(0.98, 0.8 + (hits.length - 1) * 0.05)
      : Math.min(0.8, 0.5 + (hits.length - 1) * 0.1);
    const preview = s.replace(/\s+/g, " ").trim().slice(0, 45) + (s.length > 45 ? "…" : "");
    return { confidence: conf, label: hits[0].label, preview };
  }
  function pageHasClickFixText() {
    let t = "";
    try {
      t = (document.body?.innerText || "").slice(0, 20000);
    } catch {}
    const run = RUN_DIALOG.some((re) => re.test(t));
    const fake = FAKE_VERIFY.some((re) => re.test(t));
    return { run, fake };
  }

  let clickFixWarned = false;
  window.addEventListener("kedayam:clip", (e) => {
    if (STATE.settings?.detection?.clickFixGuard === false) return;
    if (clickFixWarned) return;
    const verdict = classifyClip(e.detail?.text || "");
    if (!verdict) return;
    clickFixWarned = true;
    const ctx = pageHasClickFixText();
    const corroborated = ctx.run || ctx.fake;
    // Mirror of lib/clipboardGuard.js SAFE_CLIPBOARD_TEXT.
    const SAFE_CLIP = "[cleared by Kedayam — a malicious command was removed]";
    const clearClipboard = () => {
      try {
        navigator.clipboard?.writeText(SAFE_CLIP)?.catch(() => {});
      } catch {}
    };
    // Best-effort automatic neutralize now (may be a no-op without focus/gesture);
    // the modal's "Clear my clipboard" button re-does it under the user's click,
    // which reliably overwrites the planted command.
    let cleared = false;
    try {
      clearClipboard();
      cleared = true;
    } catch {}
    log({ kind: "clickfix-blocked", host: location.hostname, severity: "critical" });
    showWarningModal({
      severity: "critical",
      title: "Do not paste — this page copied a system command",
      body: `${location.hostname} just placed a ${verdict.label} command on your clipboard${corroborated ? " and is telling you to run it" : ""}. This is the "ClickFix" malware trick. Never paste it into PowerShell, the Run dialog (Win+R), or a terminal.${cleared ? " Kedayam tried to clear your clipboard — use “Clear my clipboard” to be sure." : ""}`,
      items: [{ label: "Copied command", value: verdict.preview }],
      onClearClipboard: clearClipboard,
      onTrust: () => sessionTrusted.add(location.hostname),
    });
  });

  // ---------- Tech-support scam / scareware guard ----------
  // Inline mirror of lib/scarewareGuard.js. Detects "your PC is infected — call
  // this number" pages that lock the screen / spam dialogs. Conservative:
  // alarmist text must pair with a call-to-action or a UI-lock cue.
  const SCARE_THREAT = [
    /\byour\s+(computer|pc|system|device|windows)\s+(is|has been|may be)\s+(infected|locked|blocked|compromised|at risk)\b/i,
    /\b(virus(es)?|trojan|spyware|malware)\s+(detected|found|alert)\b/i,
    /\b(security|system)\s+(alert|warning|breach)\b/i,
    /\byour\s+(data|files|identity|information)\s+(is|are|may be)\s+(at risk|stolen|compromised|encrypted)\b/i,
  ];
  const SCARE_CTA = [
    /\bcall\s+(us|now|immediately|microsoft|apple|windows|support|toll[- ]?free)\b/i,
    /\b(toll[- ]?free|helpline|support\s+(line|number|team))\b/i,
    /\bdo\s+not\s+(close|restart|shut\s*down|turn\s*off|ignore)\b/i,
    /\bcall\s*[:.]?\s*(\+?\d[\d\s().-]{7,}\d)\b/i,
  ];
  const SCARE_VENDOR =
    /\b(windows\s+defender|microsoft\s+(security|support)|apple\s+support|norton|mcafee)\b/i;
  let scarewareWarned = false;
  function checkScareware() {
    if (STATE.settings?.detection?.scarewareGuard === false) return;
    if (scarewareWarned) return;
    let text = "";
    try {
      text = (document.body?.innerText || "").slice(0, 20000);
    } catch {}
    if (!text) return;
    const threat = SCARE_THREAT.filter((re) => re.test(text)).length;
    const cta = SCARE_CTA.filter((re) => re.test(text)).length;
    const vendor = SCARE_VENDOR.test(text);
    let hasTel = false;
    try {
      hasTel = !!document.querySelector('a[href^="tel:"]');
    } catch {}
    const fullscreen = !!document.fullscreenElement;
    const structural = [hasTel, fullscreen].filter(Boolean).length;
    let score =
      Math.min(threat, 2) * 0.28 + Math.min(cta, 2) * 0.3 + (vendor ? 0.18 : 0) + structural * 0.2;
    const corroborated =
      (threat >= 1 && (cta >= 1 || structural >= 1)) || (cta >= 1 && structural >= 1);
    if (!corroborated || score < 0.6) return;
    scarewareWarned = true;
    log({ kind: "scareware-warn", host: location.hostname, severity: "high" });
    showWarningModal({
      severity: "high",
      title: "This looks like a tech-support scam",
      body: `${location.hostname} is showing alarming "virus/locked" warnings and urging you to call a number or not close the page. Real security software never does this. Do not call any number shown, and do not grant remote access. Close this tab.`,
      items: [
        {
          label: "Why flagged",
          value: vendor ? "fake security-vendor alert" : "scareware pattern",
        },
      ],
      onTrust: () => sessionTrusted.add(location.hostname),
    });
  }

  // ---------- Malicious-download guard ----------
  // Warns before a dangerous executable download on a low-trust page. Gated to
  // keep false positives near zero: only fires for executable extensions AND
  // when the current page is rated suspicious/dangerous (or no verdict yet on
  // a cross-origin executable).
  const DANGEROUS_EXT =
    /\.(exe|scr|msi|bat|cmd|com|hta|vbs|vbe|js|jse|wsf|ps1|jar|apk|dmg|pkg|iso|img|lnk|reg|gadget|cpl)(\?|#|$)/i;
  const downloadBypass = new Set();
  document.addEventListener(
    "click",
    (e) => {
      if (STATE.settings?.detection?.downloadGuard === false) return;
      const a = e.target instanceof Element ? e.target.closest("a[href]") : null;
      if (!a) return;
      const href = a.getAttribute("href") || "";
      const hasDownloadAttr = a.hasAttribute("download");
      const looksDangerous =
        DANGEROUS_EXT.test(href) ||
        (hasDownloadAttr && DANGEROUS_EXT.test(a.getAttribute("download") || ""));
      if (!looksDangerous) return;
      if (downloadBypass.has(href)) return;
      const status = STATE.lastResult?.status;
      const lowTrust = status === "suspicious" || status === "dangerous";
      let crossOrigin = false;
      try {
        crossOrigin = new URL(href, location.href).origin !== location.origin;
      } catch {}
      if (!lowTrust && !crossOrigin) return; // trusted same-origin app download — allow
      e.preventDefault();
      e.stopPropagation();
      let ext = (href.match(DANGEROUS_EXT) || [])[1] || "executable";
      log({
        kind: "download-warn",
        host: location.hostname,
        severity: lowTrust ? "high" : "medium",
      });
      showWarningModal({
        severity: lowTrust ? "high" : "medium",
        title: "This download could run code on your device",
        body: `${location.hostname} is offering a .${ext} file${lowTrust ? `, and Kedayam rated this page ${status}` : ""}. Executable downloads are a common malware-delivery method. Only continue if you fully trust this source.`,
        items: [{ label: "File type", value: "." + ext }],
        onContinue: () => {
          downloadBypass.add(href);
          try {
            a.click();
          } catch {
            try {
              window.location.href = new URL(href, location.href).href;
            } catch {}
          }
        },
        onTrust: () => sessionTrusted.add(location.hostname),
      });
    },
    true,
  );

  function injectMainWorldShim() {
    try {
      // CSP-safe: load an external file via chrome.runtime.getURL — no inline code.
      const url = chrome.runtime.getURL("content/main-world-shim.js");
      const s = document.createElement("script");
      s.src = url;
      s.async = false;
      s.onload = () => s.remove();
      s.onerror = () => {
        debug("shim load failed");
        s.remove();
      };
      (document.head || document.documentElement).appendChild(s);
    } catch (e) {
      debug("shim inject failed", e);
    }
  }

  // ---------- Page-context collection (clone detection) ----------
  // Run once on idle after the DOM is reasonably stable. We only collect
  // *origins* of assets, never their contents. Nothing leaves the device.
  function collectPageContext() {
    try {
      const origin = location.origin;
      const pick = (sel, attr) =>
        Array.from(document.querySelectorAll(sel))
          .map((el) => el.getAttribute(attr))
          .filter(Boolean)
          .slice(0, 60);
      // --- DOM auth signals for phishing heuristics ---
      const formEls = Array.from(document.querySelectorAll("form")).slice(0, 10);
      const forms = formEls.map((f) => {
        const inputs = Array.from(f.querySelectorAll("input"));
        const hasPassword = inputs.some((i) => (i.type || "").toLowerCase() === "password");
        const hasEmailLike = inputs.some((i) => {
          const t = (i.type || "").toLowerCase();
          const n = (
            (i.name || "") +
            " " +
            (i.id || "") +
            " " +
            (i.autocomplete || "")
          ).toLowerCase();
          return t === "email" || /email|user(name)?|login|account/.test(n);
        });
        const hasOtp = inputs.some((i) => {
          const n = ((i.name || "") + " " + (i.id || "") + (i.autocomplete || "")).toLowerCase();
          return (
            /otp|one[-_ ]?time|2fa|mfa|verification[-_ ]?code/.test(n) ||
            (i.inputMode === "numeric" && i.maxLength >= 4 && i.maxLength <= 8)
          );
        });
        return {
          action: f.getAttribute("action") || "",
          method: f.getAttribute("method") || "post",
          hasPassword,
          hasEmailLike,
          hasOtp,
          hiddenCount: inputs.filter((i) => (i.type || "").toLowerCase() === "hidden").length,
          fieldsCount: inputs.length,
          insideIframe: window.top !== window.self,
        };
      });
      // Detect any password field even outside a <form> (modern SPAs).
      const hasPasswordField = !!document.querySelector("input[type=password]");
      // Visible text excerpt for brand/auth phrasing detection.
      // Hidden DOM (display:none, visibility:hidden, opacity:0, aria-hidden,
      // off-screen traps, <script>/<style>/<template>/<noscript>) MUST NOT
      // contribute to phishing keyword scoring or explanation text — that
      // would let attackers inflate confidence via invisible payloads and
      // would muddy the user-facing reasons we surface. Only collect text
      // a real user would plausibly see on the page.
      const titleText = (document.title || "").trim();
      const textNodes = Array.from(
        document.querySelectorAll("h1, h2, h3, button, a, label, p, span"),
      ).slice(0, 400);
      const visibleText = (
        titleText +
        " " +
        textNodes
          .filter(isUserVisible)
          .map((n) => (n.textContent || "").trim())
          .filter(Boolean)
          .join(" ")
      ).slice(0, 4000);
      // OAuth-style buttons by visible text.
      const oauthRe = /sign in with (google|microsoft|apple|facebook|github|twitter|x|linkedin)/i;
      const oauthButtons = Array.from(
        new Set(
          Array.from(document.querySelectorAll("button, a, [role=button]"))
            .map((el) => (el.textContent || "").trim())
            .map((t) => t.match(oauthRe)?.[1]?.toLowerCase())
            .filter(Boolean),
        ),
      );
      // Issue NEW-02 — populate an authFlow snapshot the trust engine can
      // arbitrate over. Computed locally; never includes secret values.
      const authFlow = buildAuthFlowSnapshot({
        pageOrigin: origin,
        forms,
        hasPasswordField,
        oauthButtons,
        inIframe: window.top !== window.self,
        referrerOrigin: safeOrigin(document.referrer),
      });
      const ctx = {
        pageOrigin: origin,
        title: document.title || "",
        visibleText,
        forms,
        hasPasswordField,
        oauthButtons,
        topLevelIframe: window.top !== window.self,
        scripts: pick("script[src]", "src"),
        styles: pick("link[rel='stylesheet'][href]", "href"),
        images: pick("img[src]", "src"),
        favicon: document.querySelector("link[rel~='icon']")?.getAttribute("href") || null,
        authFlow,
      };
      try {
        chrome.runtime.sendMessage(
          { type: "pageContext", context: ctx },
          () => void chrome.runtime.lastError,
        );
      } catch {}
    } catch {}
  }

  // Accessibility-aware visibility check. Excludes display:none, visibility:
  // hidden, opacity:0, aria-hidden subtrees, off-screen "trap" nodes, and
  // hostile script/style/template/noscript content. Keeps legitimately
  // visible auth prompts and accessible labels intact. Best-effort: failures
  // default to "visible" so we never silently drop real user-facing text.
  function isUserVisible(el) {
    try {
      if (!el || !(el instanceof Element)) return false;
      const tag = el.tagName;
      if (tag === "SCRIPT" || tag === "STYLE" || tag === "TEMPLATE" || tag === "NOSCRIPT")
        return false;
      // aria-hidden anywhere up the tree means assistive tech ignores it —
      // so should we.
      if (el.closest('[aria-hidden="true"]')) return false;
      const cs = typeof getComputedStyle === "function" ? getComputedStyle(el) : null;
      if (cs) {
        if (cs.display === "none" || cs.visibility === "hidden" || cs.visibility === "collapse")
          return false;
        const op = parseFloat(cs.opacity);
        if (!Number.isNaN(op) && op === 0) return false;
      }
      // Off-screen traps: zero-area or pushed far outside the viewport in a
      // way no real user would ever see. We only reject *fully* zero-sized
      // boxes; sticky/fixed nav with non-zero size stays in.
      if (typeof el.getBoundingClientRect === "function") {
        const r = el.getBoundingClientRect();
        if (r && r.width === 0 && r.height === 0) return false;
      }
      return true;
    } catch {
      return true;
    }
  }

  function safeOrigin(u) {
    if (!u) return "";
    try {
      return new URL(u).origin;
    } catch {
      return "";
    }
  }
  // Build the behavioral auth-flow snapshot from already-collected DOM
  // facts. Pure: no secret values, no DOM scraping of input values, no
  // network. Returned object matches AuthFlowGraph.serialize() shape so
  // it can be consumed unchanged by trustDecay() and the behavioral rule
  // registry (extension/lib/rules/behavioral/*).
  function buildAuthFlowSnapshot(info) {
    const steps = [];
    const anomalies = [];
    const pageOrigin = info.pageOrigin || "";
    steps.push({
      id: "s1",
      kind: "entry",
      origin: pageOrigin,
      inIframe: !!info.inIframe,
      t: Date.now(),
    });

    // Iframe-origin-swap: this frame holds a password field but is embedded
    // under a different parent origin (we can only observe via referrer).
    if (
      info.hasPasswordField &&
      info.inIframe &&
      info.referrerOrigin &&
      info.referrerOrigin !== pageOrigin
    ) {
      steps.push({
        id: "s2",
        kind: "credential",
        origin: pageOrigin,
        inIframe: true,
        t: Date.now(),
      });
      anomalies.push({
        id: "iframe-origin-swap",
        severity: "medium",
        explain: `Credential entry happens inside an iframe on ${pageOrigin}, embedded under ${info.referrerOrigin}.`,
      });
    }
    // Credential-relay: any password-bearing form whose action points to an
    // origin we have not "visited" (= page origin). Behavioral, brand-agnostic.
    for (const f of info.forms || []) {
      if (!f.hasPassword) continue;
      const post = (() => {
        try {
          return new URL(f.action || "", location.href).origin;
        } catch {
          return "";
        }
      })();
      if (post && post !== pageOrigin) {
        steps.push({
          id: `s${steps.length + 1}`,
          kind: "credential",
          origin: pageOrigin,
          postOrigin: post,
          t: Date.now(),
        });
        anomalies.push({
          id: "credential-relay",
          severity: "high",
          explain: `Credential step targets ${post}, which is not part of the visited auth flow.`,
        });
      }
    }
    // OAuth surface — we record an oauth step when a recognised OAuth button
    // exists, so the background can correlate with redirect-chain origins to
    // detect oauth-token-drift downstream.
    if ((info.oauthButtons || []).length) {
      steps.push({
        id: `s${steps.length + 1}`,
        kind: "oauth",
        origin: pageOrigin,
        t: Date.now(),
        tags: info.oauthButtons.slice(0, 4),
      });
    }
    return { steps, anomalies };
  }
  function schedulePageContext() {
    const run = () => {
      if (typeof requestIdleCallback === "function") {
        requestIdleCallback(collectPageContext, { timeout: 2000 });
      } else {
        setTimeout(collectPageContext, 800);
      }
      // Scareware text is usually present at load; re-check shortly after in
      // case the lock screen is injected dynamically.
      setTimeout(checkScareware, 1200);
    };
    if (document.readyState === "complete" || document.readyState === "interactive") run();
    else document.addEventListener("DOMContentLoaded", run, { once: true });
  }
  schedulePageContext();
  // Catch a fullscreen-lock scam that engages after a user gesture.
  document.addEventListener("fullscreenchange", () => setTimeout(checkScareware, 300));

  // Re-collect if a password field appears post-load (SPA / lazy auth modal).
  // Throttled via a token-bucket Budget so a mutation storm cannot dominate
  // the main thread. The observer self-disconnects after a single
  // password-field detection or after 15s, whichever comes first.
  const mutationBudget = { max: 12, windowMs: 1000, hits: [] };
  function mutationAllowed() {
    const cutoff = Date.now() - mutationBudget.windowMs;
    while (mutationBudget.hits.length && mutationBudget.hits[0] < cutoff)
      mutationBudget.hits.shift();
    if (mutationBudget.hits.length >= mutationBudget.max) return false;
    mutationBudget.hits.push(Date.now());
    return true;
  }
  let recollected = false;
  let mo = null;
  let moTimeout = null;
  try {
    mo = new MutationObserver(() => {
      if (recollected) return;
      if (!mutationAllowed()) return;
      // Defer to idle so we never block input handling.
      const run = () => {
        if (recollected) return;
        if (document.querySelector("input[type=password]")) {
          recollected = true;
          try {
            mo && mo.disconnect();
          } catch {}
          if (moTimeout) {
            clearTimeout(moTimeout);
            moTimeout = null;
          }
          setTimeout(collectPageContext, 250);
        }
      };
      if (typeof requestIdleCallback === "function") requestIdleCallback(run, { timeout: 500 });
      else setTimeout(run, 0);
    });
    mo.observe(document.documentElement, { childList: true, subtree: true });
    moTimeout = setTimeout(() => {
      try {
        mo && mo.disconnect();
      } catch {}
      mo = null;
    }, 15000);
  } catch {}
  // Defensive listener cleanup on page hide — prevents listener leaks across
  // bfcache restores and long-lived SPAs.
  window.addEventListener(
    "pagehide",
    () => {
      try {
        mo && mo.disconnect();
      } catch {}
      if (moTimeout) {
        clearTimeout(moTimeout);
        moTimeout = null;
      }
      sessionTrusted.clear();
    },
    { once: true },
  );

  function maybeWarnPermission(req) {
    if (!STATE.settings?.detection?.permissionMonitoring) return;
    const status = STATE.lastResult?.status;
    if (status !== "suspicious" && status !== "dangerous") return;
    const rawWhat =
      req?.what ||
      (req?.video
        ? "camera"
        : req?.audio
          ? "microphone"
          : req?.geolocation
            ? "location"
            : "device");
    // Allowlist: the legitimate MAIN-world shim only ever emits these values.
    // Any page-dispatched event with a different `what` is normalized to
    // "device" so untrusted strings can never reach innerHTML.
    const ALLOWED_PERMS = new Set(["camera", "microphone", "location", "clipboard"]);
    const what = ALLOWED_PERMS.has(rawWhat) ? rawWhat : "device";
    const r = root();
    const toast = document.createElement("div");
    toast.className = "ked-toast";
    toast.dataset.severity = "dangerous";
    toast.innerHTML = `
      <span class="ked-toast-dot"></span>
      <div>
        <div style="font-weight:600">${escapeHtml(location.hostname)} requested ${escapeHtml(what)}</div>
        <div class="ked-tiny">This site has a low trust score. Deny if you didn't initiate this.</div>
      </div>`;
    r.appendChild(toast);
    setTimeout(() => toast.remove(), 8000);
    log({ kind: "permission-warn", host: location.hostname, what });
  }

  function log(entry) {
    try {
      chrome.runtime.sendMessage({ type: "logEvent", entry }, () => void chrome.runtime.lastError);
    } catch {}
  }

  // ---------- Bootstrap ----------
  chrome.runtime.sendMessage({ type: "getSettings" }, (s) => {
    if (chrome.runtime.lastError) return;
    if (s && typeof s === "object") {
      STATE.settings = s;
      STATE.settingsLoaded = true;
    }
  });

  // Issue NEW-03 — progressive UX. The trust engine emits a 5-band
  // suspicion model (informational/contextual/suspicious/highRisk/dangerous)
  // alongside the coarse status. Map each band to the right surface so
  // calibration nuance reaches the user and modal fatigue stays low.
  const trustBannerShown = new Set(); // host -> band, suppresses repeat banners
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type !== "kedayam:trust") return;
    STATE.lastResult = msg.result;
    // A permanently trusted domain never surfaces trust banners or modals
    // again — that is exactly what "Always trust this site" promises. Paste,
    // file and clipboard protections (which guard the user's own data, not
    // the site's reputation) stay active.
    if (isPermanentlyTrusted()) return;
    const susp = msg.result.suspicion || {
      level:
        msg.result.status === "dangerous"
          ? "dangerous"
          : msg.result.status === "suspicious"
            ? "suspicious"
            : "informational",
      modal: msg.result.status === "dangerous" ? "hard" : "none",
      popupBanner: msg.result.status !== "safe",
      blockingUx: msg.result.status === "dangerous",
    };
    const bannerKey = `${location.hostname}|${susp.level}`;
    const showBanner = susp.popupBanner && !trustBannerShown.has(bannerKey);
    if (showBanner) {
      trustBannerShown.add(bannerKey);
      showToast(msg.result);
    }
    // dangerous → hard modal (blocking). high-risk → soft modal (dismissible).
    // suspicious/contextual → toast banner only (already shown above).
    if (susp.modal === "hard") {
      showWarningModal({
        severity: "critical",
        title: "This page shows strong signs of being unsafe",
        body: `Kedayam evaluated ${msg.result.host} and gave it a trust score of ${msg.result.score}/100. Avoid entering credentials or personal information.`,
        items: msg.result.signals
          .filter((s) => s.severity !== "info")
          .slice(0, 5)
          .map((s) => ({ label: s.title, value: s.severity })),
        onLeave: () => leaveToSafety(),
        // No session-only trust here: on a trust verdict the meaningful choices
        // are leave, verify, permanently trust, or continue once. A third
        // "trust for the session" button only diluted them.
        onAlwaysTrust: () => trustPermanently(),
        verifyUrl: virusTotalUrl(),
      });
    } else if (susp.modal === "soft" && !sessionTrusted.has(location.hostname)) {
      showWarningModal({
        severity: "medium",
        title: "Review this page before signing in",
        body: `Kedayam flagged behavioral signals on ${msg.result.host} (score ${msg.result.score}/100). You can continue, but verify the address and avoid entering MFA codes if you didn't initiate this flow.`,
        items: msg.result.signals
          .filter((s) => s.severity !== "info")
          .slice(0, 4)
          .map((s) => ({ label: s.title, value: s.severity })),
        onLeave: () => leaveToSafety(),
        onContinue: () => sessionTrusted.add(location.hostname),
        onAlwaysTrust: () => trustPermanently(),
        verifyUrl: virusTotalUrl(),
      });
    }
  });
})();
