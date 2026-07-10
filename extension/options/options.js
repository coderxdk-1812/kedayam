import {
  getProtectionOverview,
  protectionSummary,
  PROTECTION_LIMITS,
} from "../lib/protectionCatalog.js";

const send = (msg) => new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
let settings = null;

function getPath(obj, path) {
  return path.split(".").reduce((a, k) => a?.[k], obj);
}
function setPath(obj, path, val) {
  const keys = path.split(".");
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    cur[keys[i]] = cur[keys[i]] || {};
    cur = cur[keys[i]];
  }
  cur[keys[keys.length - 1]] = val;
}

async function init() {
  settings = await send({ type: "getSettings" });

  for (const el of document.querySelectorAll("[data-key]")) {
    const key = el.dataset.key;
    el.checked = !!getPath(settings, key);
    el.addEventListener("change", () => save({ [topKey(key)]: nestedPatch(key, el.checked) }));
  }

  const sens = document.getElementById("sensitivity");
  sens.value = settings.detection.sensitivity;
  sens.addEventListener("change", () => save({ detection: { sensitivity: sens.value } }));

  document.getElementById("gsb").value = settings.apiKeys.googleSafeBrowsing || "";
  document.getElementById("vt").value = settings.apiKeys.virusTotal || "";
  document
    .getElementById("gsb")
    .addEventListener("change", (e) =>
      save({ apiKeys: { googleSafeBrowsing: e.target.value.trim() } }),
    );
  document
    .getElementById("vt")
    .addEventListener("change", (e) => save({ apiKeys: { virusTotal: e.target.value.trim() } }));

  renderProtectionOverview();

  renderAllowlist();
  document.getElementById("allow-add").addEventListener("click", addAllow);
  document.getElementById("allow-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") addAllow();
  });

  document.getElementById("clear-cache").addEventListener("click", async () => {
    await send({ type: "clearCaches" });
    toast("Cleared cached evaluations");
  });

  const feedBtn = document.getElementById("feed-refresh");
  if (feedBtn) {
    feedBtn.addEventListener("click", async () => {
      const status = document.getElementById("feed-status");
      feedBtn.disabled = true;
      if (status) status.textContent = "Updating…";
      const res = await send({ type: "refreshThreatFeed" });
      const n = res && typeof res.count === "number" ? res.count : 0;
      if (status) status.textContent = `Loaded ${n.toLocaleString()} blocklist entries.`;
      feedBtn.disabled = false;
      toast("Threat feed updated");
    });
  }

  // Sidebar active link
  document.querySelectorAll(".sidebar nav a").forEach((a) => {
    a.addEventListener("click", () => {
      document
        .querySelectorAll(".sidebar nav a")
        .forEach((x) => x.classList.toggle("active", x === a));
    });
  });
}

function topKey(path) {
  return path.split(".")[0];
}
function nestedPatch(path, val) {
  const keys = path.split(".").slice(1);
  if (!keys.length) return val;
  const out = {};
  let cur = out;
  for (let i = 0; i < keys.length - 1; i++) {
    cur[keys[i]] = {};
    cur = cur[keys[i]];
  }
  cur[keys[keys.length - 1]] = val;
  return out;
}

async function save(patch) {
  settings = await send({ type: "saveSettings", patch });
  renderProtectionOverview(); // keep the live on/off state in sync
  toast("Saved");
}

async function addAllow() {
  const input = document.getElementById("allow-input");
  const v = input.value
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
  if (!v || settings.allowlist.includes(v)) {
    input.value = "";
    return;
  }
  const next = [...settings.allowlist, v];
  settings = await send({ type: "saveSettings", patch: { allowlist: next } });
  input.value = "";
  renderAllowlist();
}

function renderProtectionOverview() {
  const host = document.getElementById("protection-overview");
  if (!host) return;
  const rows = getProtectionOverview(settings);
  host.innerHTML = rows
    .map((r) => {
      const state = r.enabled
        ? '<span class="pill on">On</span>'
        : '<span class="pill off">Off</span>';
      const core = r.core ? '<span class="pill core">Always on</span>' : "";
      return `<div class="protection-item ${r.enabled ? "" : "dim"}">
        <div class="pi-head">
          <span class="pi-title">${escapeHtml(r.title)}</span>
          <span class="uplift u-${r.upliftRating}">${r.upliftRating} uplift</span>
          ${r.core ? core : state}
        </div>
        <div class="pi-what">${escapeHtml(r.what)}</div>
        <div class="pi-limit"><strong>Limit:</strong> ${escapeHtml(r.limit)}</div>
      </div>`;
    })
    .join("");

  const s = protectionSummary(settings);
  const summary = document.getElementById("protection-summary");
  if (summary) {
    summary.textContent = `${s.active} of ${s.total} layers active · ${s.highActive} rated HIGH uplift.`;
  }

  const limits = document.getElementById("protection-limits");
  if (limits) {
    limits.innerHTML = PROTECTION_LIMITS.map((l) => `<li>${escapeHtml(l)}</li>`).join("");
  }
}

function renderAllowlist() {
  const ul = document.getElementById("allow-list");
  ul.innerHTML = settings.allowlist
    .map(
      (d) =>
        `<li>${escapeHtml(d)} <button data-d="${escapeHtml(d)}" aria-label="Remove">×</button></li>`,
    )
    .join("");
  ul.querySelectorAll("button").forEach((b) =>
    b.addEventListener("click", async () => {
      const next = settings.allowlist.filter((x) => x !== b.dataset.d);
      settings = await send({ type: "saveSettings", patch: { allowlist: next } });
      renderAllowlist();
    }),
  );
}

function escapeHtml(s) {
  return String(s).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

let toastT;
function toast(msg) {
  const t = document.getElementById("saved-toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastT);
  toastT = setTimeout(() => t.classList.remove("show"), 1400);
}

init();
