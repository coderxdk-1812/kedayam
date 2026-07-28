import { explainVerdict } from "../lib/explanation.js";

const $ = (sel) => document.querySelector(sel);
const send = (msg) =>
  new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (response) => {
        if (chrome.runtime.lastError)
          resolve({ ok: false, error: chrome.runtime.lastError.message });
        else resolve(response);
      });
    } catch (error) {
      resolve({ ok: false, error: String(error?.message || error) });
    }
  });

const STATUS_COPY = {
  loading: { label: "Scanning", sub: "Evaluating browser signals." },
  safe: { label: "Safe", sub: "No notable risks detected on this page." },
  suspicious: { label: "Review", sub: "A few signals look unusual. Proceed with care." },
  dangerous: { label: "High risk", sub: "Strong phishing or malicious indicators detected." },
};

let currentTab = null;
let currentResult = null;

async function init() {
  try {
    // Keep the footer version in sync with the manifest so it never drifts.
    const verEl = document.getElementById("ext-version");
    if (verEl) verEl.textContent = `v${chrome.runtime.getManifest().version}`;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;
    if (!tab?.url || !/^https?:/.test(tab.url)) {
      // Browser-internal pages (chrome://, the new-tab page, the web store, PDF
      // viewer, local files) can't be scanned by design — there's nothing to
      // phish. Say so plainly so an empty score doesn't read as "broken".
      setHero({ score: "—", status: "loading", host: hostLabel(tab?.url) });
      $("#status-label").textContent = "Not scannable";
      $("#status-sub").textContent =
        "Open a normal website (a page starting with http:// or https://) and Kedayam will score it here.";
      renderSignals(null);
      renderDetails(null);
      await renderActivity();
      return;
    }
    $("#host").textContent = new URL(tab.url).host;
    await refresh(false);
    await renderActivity();
  } catch (error) {
    showError(error);
  }
}

async function refresh(force) {
  setHero({ status: "loading" });
  // The MV3 service worker may be asleep when the popup opens; the first
  // message wakes it, but a cold start can occasionally miss. Retry once
  // before surfacing an error so a transient wake-up never reads as "no score".
  let result = await send({ type: "scan", url: currentTab.url, tabId: currentTab.id, force });
  if (!result || result.ok === false) {
    await new Promise((r) => setTimeout(r, 250));
    result = await send({ type: "scan", url: currentTab.url, tabId: currentTab.id, force });
  }
  // Belt-and-suspenders: if the tabId is ever rejected by validation, fall back
  // to a URL-only scan so the score still loads instead of reading "UNAVAILABLE".
  if (!result || result.ok === false) {
    result = await send({ type: "scan", url: currentTab.url, force });
  }
  if (!result || result.ok === false) {
    showError(result?.error || "Unable to contact the Kedayam service worker.");
    return;
  }
  currentResult = result;
  setHero({ score: result.score, status: result.status, host: result.host });
  renderSignals(result);
  renderDetails(result);
}

// Friendly label for a non-scannable page (chrome://, new tab, files, store).
function hostLabel(url) {
  if (!url) return "This page";
  try {
    if (url.startsWith("chrome://") || url.startsWith("edge://") || url.startsWith("about:"))
      return "Browser page";
    if (url.startsWith("chrome-extension://") || url.startsWith("moz-extension://"))
      return "Extension page";
    if (url.startsWith("file:")) return "Local file";
    if (/chrome\.google\.com\/webstore|chromewebstore\.google\.com/.test(url))
      return "Chrome Web Store";
    return new URL(url).host || "This page";
  } catch {
    return "This page";
  }
}

function setHero({ score, status, host }) {
  if (host) $("#host").textContent = host;
  if (score !== undefined) $("#score").textContent = score;
  if (status) {
    const copy = STATUS_COPY[status] || STATUS_COPY.loading;
    const hero = $("#hero");
    hero.dataset.status = status;
    $("#status-label").textContent = copy.label;
    $("#status-sub").textContent = copy.sub;
    const ring = $("#ring-progress");
    const pct = typeof score === "number" ? score / 100 : 0;
    const C = 2 * Math.PI * 52;
    ring.style.strokeDashoffset = (C * (1 - pct)).toFixed(2);
  }
}

function renderSignals(result) {
  const root = $("#panel-signals");
  const all = result?.signals || [];
  if (!all.length && !result) {
    root.innerHTML = `<div class="empty">No page signals yet.</div>`;
    return;
  }

  // Calm, deterministic explanation rendered above the raw signal list.
  // Tone rules: technical, factual, no panic words ("DANGER", "HACKER").
  const explanation = result ? explainVerdict(result) : null;
  const explainBlock = explanation
    ? `
    <div class="explain" data-verdict="${escapeHtml(explanation.verdict)}">
      <div class="explain-headline">${escapeHtml(explanation.headline)}</div>
      ${explanation.summary ? `<p class="explain-summary">${escapeHtml(explanation.summary)}</p>` : ""}
      ${
        explanation.bullets?.length
          ? `
        <div class="explain-sub">What we noticed</div>
        <ul class="explain-bullets">${explanation.bullets
          .map((b) => `<li>${escapeHtml(b)}</li>`)
          .join("")}</ul>`
          : ""
      }
      ${
        explanation.recommendation
          ? `
        <div class="explain-reco"><strong>What to do:</strong> ${escapeHtml(explanation.recommendation)}</div>`
          : ""
      }
      ${
        explanation.triggeredRules?.length
          ? `
        <details class="explain-tech">
          <summary>Technical details</summary>
          <div class="explain-rules">Triggered protections: ${explanation.triggeredRules
            .slice(0, 4)
            .map((r) => `<code>${escapeHtml(r)}</code>`)
            .join(" · ")}</div>
        </details>`
          : ""
      }
    </div>`
    : "";

  // Show fired signals first (sorted by impact), then passing checks.
  const fired = all
    .filter((s) => (s.contribution || 0) < 0)
    .sort((a, b) => (a.contribution || 0) - (b.contribution || 0));
  const caps = all.filter((s) => s.cap);
  const passed = all.filter((s) => (s.contribution || 0) === 0 && s.severity === "info");

  const firedHtml = fired.length
    ? `
    <div class="group-label">Why this score</div>
    ${fired.map(signalCard).join("")}`
    : "";

  const capHtml = caps.length
    ? `
    <div class="group-label">Trust caps</div>
    ${caps.map(signalCard).join("")}`
    : "";

  const passedHtml = passed.length
    ? `
    <div class="group-label">Passed checks</div>
    ${passed.map(signalCard).join("")}`
    : "";

  root.innerHTML = explainBlock + riskMeter(result) + firedHtml + capHtml + passedHtml;
}

function riskMeter(result) {
  const phishing = Math.round((result?.phishingConfidence || 0) * 100);
  const clone = Math.round((result?.cloneConfidence || 0) * 100);
  const auth = result?.authRisk || "none";
  // Issue NEW-03 — surface the progressive suspicion band so the popup
  // reflects the same calibration the content-script UX uses (informational
  // / contextual / suspicious / high-risk / dangerous).
  const susp = result?.suspicion?.level;
  const suspChip =
    susp && susp !== "informational"
      ? `<span class="susp susp-${escapeHtml(susp)}">${escapeHtml(susp)}</span>`
      : "";
  if (!phishing && !clone && auth === "none" && !suspChip) return "";
  return `<div class="risk-strip">
    ${suspChip}
    <span>Phishing ${phishing}%</span>
    <span>Clone ${clone}%</span>
    <span>Auth ${escapeHtml(auth)}</span>
  </div>`;
}

function signalCard(s) {
  const cat = s.category ? `<span class="cat">${escapeHtml(s.category)}</span>` : "";
  const delta = s.cap
    ? `<span class="delta">≤${s.maxScore}</span>`
    : (s.contribution || 0) < 0
      ? `<span class="delta">${s.contribution}</span>`
      : "";
  const conf =
    typeof s.confidence === "number" && s.confidence < 1 && s.contribution
      ? `<span class="conf">${Math.round(s.confidence * 100)}% conf</span>`
      : "";
  return `
    <article class="signal" data-sev="${escapeHtml(s.severity)}">
      <span class="pin" aria-hidden="true"></span>
      <div>
        <div class="title">${escapeHtml(s.title)}${delta}</div>
        <div class="meta">${cat}${conf}</div>
        ${s.detail ? `<div class="detail">${escapeHtml(s.detail)}</div>` : ""}
      </div>
    </article>`;
}

function renderDetails(result) {
  const root = $("#panel-details");
  if (!result) {
    root.innerHTML = `<div class="empty">Details appear after a page scan.</div>`;
    return;
  }
  const apiState = result.safeBrowsing || {};
  root.innerHTML = `
    <article class="detail-card">
      <strong>Final URL</strong>
      <code>${escapeHtml(result.url)}</code>
    </article>
    <article class="detail-card">
      <strong>Root domain</strong>
      <span class="detail">${escapeHtml(result.root || result.host)}</span>
    </article>
    <article class="detail-card">
      <strong>Reputation APIs</strong>
      <span class="detail">Google Safe Browsing: ${apiLabel(apiState.google)} · VirusTotal: ${apiLabel(apiState.virusTotal)}</span>
    </article>`;
}

async function renderActivity() {
  const [list, metrics] = await Promise.all([
    send({ type: "getActivity" }),
    send({ type: "getMetrics" }),
  ]);
  const root = $("#panel-activity");
  const m = metrics && metrics.ok !== false ? metrics : {};
  // Local, on-device tally — nothing here is ever uploaded.
  const statsHtml = `
    <div class="stats-row">
      <div class="stat"><div class="stat-num">${m.threatsPrevented || 0}</div><div class="stat-lbl">Threats blocked</div></div>
      <div class="stat"><div class="stat-num">${m.pastesBlocked || 0}</div><div class="stat-lbl">Pastes protected</div></div>
      <div class="stat"><div class="stat-num">${m.clickfixBlocked || 0}</div><div class="stat-lbl">ClickFix stopped</div></div>
    </div>
    <div class="stats-note">Counted locally on this device. Nothing is uploaded.</div>`;
  if (!Array.isArray(list) || !list.length) {
    root.innerHTML = statsHtml + `<div class="empty">No recent activity.</div>`;
    return;
  }
  root.innerHTML =
    statsHtml +
    list
      .slice(0, 20)
      .map(
        (e) => `
    <article class="activity-item">
      <div>
        <div>${escapeHtml(label(e))}</div>
        ${e.host ? `<div class="detail">${escapeHtml(e.host)}</div>` : ""}
      </div>
      <div class="when">${ago(e.at)}</div>
    </article>`,
      )
      .join("");
}

function apiLabel(api) {
  if (!api) return "not used";
  if (api.skipped) return "not configured";
  return api.malicious ? "flagged" : "clear";
}

function label(e) {
  switch (e.kind) {
    case "trust":
      return `Trust score ${e.score}/100 (${e.status})`;
    case "paste-blocked":
      return `Paste blocked (${e.count} items)`;
    case "paste-allowed":
      return `Paste allowed (${e.count} items)`;
    case "file-scan":
      return `File reviewed: ${(e.files || []).join(", ")}`;
    case "permission-warn":
      return `${e.what} request reviewed`;
    case "worker-error":
      return `Background warning`;
    default:
      return e.kind || "Activity";
  }
}

function ago(t) {
  const s = Math.max(0, Math.round((Date.now() - (t || Date.now())) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return new Date(t).toLocaleDateString();
}

function showError(error) {
  $("#panel-signals").innerHTML = `<div class="empty">${escapeHtml(String(error))}</div>`;
  $("#status-label").textContent = "Unavailable";
  $("#status-sub").textContent = "Reload the extension from chrome://extensions.";
}

function escapeHtml(s) {
  return String(s ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => {
      const active = item === tab;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll(".panel").forEach((panel) => panel.classList.add("hidden"));
    document.getElementById(`panel-${tab.dataset.tab}`).classList.remove("hidden");
    if (tab.dataset.tab === "activity") renderActivity();
  });
});

$("#rescan").addEventListener("click", () => refresh(true));
$("#trust").addEventListener("click", async () => {
  if (!currentResult?.host) return;
  await send({ type: "trustForSession", domain: currentResult.host, reason: "popup" });
  $("#trust").textContent = "Trusted";
  setTimeout(() => ($("#trust").textContent = "Trust session"), 1500);
});
$("#settings-btn").addEventListener("click", () => send({ type: "openOptions" }));

init();
