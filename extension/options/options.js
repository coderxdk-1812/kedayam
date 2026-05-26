const send = (msg) => new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
let settings = null;

function getPath(obj, path) {
  return path.split(".").reduce((a, k) => a?.[k], obj);
}
function setPath(obj, path, val) {
  const keys = path.split(".");
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) { cur[keys[i]] = cur[keys[i]] || {}; cur = cur[keys[i]]; }
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
  document.getElementById("gsb").addEventListener("change", (e) => save({ apiKeys: { googleSafeBrowsing: e.target.value.trim() } }));
  document.getElementById("vt").addEventListener("change", (e) => save({ apiKeys: { virusTotal: e.target.value.trim() } }));

  renderAllowlist();
  document.getElementById("allow-add").addEventListener("click", addAllow);
  document.getElementById("allow-input").addEventListener("keydown", (e) => { if (e.key === "Enter") addAllow(); });

  document.getElementById("clear-cache").addEventListener("click", async () => {
    await send({ type: "clearCaches" });
    toast("Cleared cached evaluations");
  });

  // Sidebar active link
  document.querySelectorAll(".sidebar nav a").forEach((a) => {
    a.addEventListener("click", () => {
      document.querySelectorAll(".sidebar nav a").forEach((x) => x.classList.toggle("active", x === a));
    });
  });
}

function topKey(path) { return path.split(".")[0]; }
function nestedPatch(path, val) {
  const keys = path.split(".").slice(1);
  if (!keys.length) return val;
  const out = {}; let cur = out;
  for (let i = 0; i < keys.length - 1; i++) { cur[keys[i]] = {}; cur = cur[keys[i]]; }
  cur[keys[keys.length - 1]] = val;
  return out;
}

async function save(patch) {
  settings = await send({ type: "saveSettings", patch });
  toast("Saved");
}

async function addAllow() {
  const input = document.getElementById("allow-input");
  const v = input.value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!v || settings.allowlist.includes(v)) { input.value = ""; return; }
  const next = [...settings.allowlist, v];
  settings = await send({ type: "saveSettings", patch: { allowlist: next } });
  input.value = "";
  renderAllowlist();
}

function renderAllowlist() {
  const ul = document.getElementById("allow-list");
  ul.innerHTML = settings.allowlist.map((d) =>
    `<li>${escapeHtml(d)} <button data-d="${escapeHtml(d)}" aria-label="Remove">×</button></li>`).join("");
  ul.querySelectorAll("button").forEach((b) =>
    b.addEventListener("click", async () => {
      const next = settings.allowlist.filter((x) => x !== b.dataset.d);
      settings = await send({ type: "saveSettings", patch: { allowlist: next } });
      renderAllowlist();
    })
  );
}

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

let toastT;
function toast(msg) {
  const t = document.getElementById("saved-toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove("show"), 1400);
}

init();