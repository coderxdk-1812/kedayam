#!/usr/bin/env node
// Kedayam — generates a self-contained test.html from the live vitest run.
// Run: bun run test:report   (regenerate whenever you want fresh results)

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, rmSync } from "node:fs";

const TMP = ".vitest-report.json";
const OUT = "test.html";

console.log("[test-report] running vitest…");
spawnSync("bunx", ["vitest", "run", "--reporter=json", `--outputFile=${TMP}`], {
  stdio: "inherit",
  timeout: 300_000,
});
const j = JSON.parse(readFileSync(TMP, "utf8"));
rmSync(TMP, { force: true });

const cwd = process.cwd();
const rel = (p) => (p && p.startsWith(cwd) ? p.slice(cwd.length + 1) : p);
const esc = (s) =>
  String(s).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
const ms = (n) => (n == null ? "" : `${Math.round(n)}ms`);

const files = j.testResults.slice().sort((a, b) => rel(a.name).localeCompare(rel(b.name)));
const totalDuration = files.reduce((a, f) => a + ((f.endTime || 0) - (f.startTime || 0)), 0);
const passRate = j.numTotalTests ? Math.round((j.numPassedTests / j.numTotalTests) * 100) : 0;
const generated = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";

const fileSections = files
  .map((f) => {
    const rows = f.assertionResults
      .map((a) => {
        const ok = a.status === "passed";
        const suite = (a.ancestorTitles || []).join(" › ");
        return `<tr class="${ok ? "" : "bad"}"><td class="s">${ok ? "✓" : "✗"}</td><td>${
          suite ? `<span class="suite">${esc(suite)}</span> ` : ""
        }${esc(a.title)}</td><td class="d">${ms(a.duration)}</td></tr>`;
      })
      .join("");
    const passed = f.assertionResults.filter((a) => a.status === "passed").length;
    const failed = f.assertionResults.length - passed;
    return `<details ${failed ? "open" : ""}>
  <summary><span class="dot ${failed ? "r" : "g"}"></span><code>${esc(rel(f.name))}</code>
    <span class="cnt">${passed} passed${failed ? ` · <b class="fail">${failed} failed</b>` : ""}</span></summary>
  <table>${rows}</table>
</details>`;
  })
  .join("\n");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Kedayam — Test Results (${j.numTotalTests})</title>
<style>
  :root{--bg:#0a0e17;--panel:#111827;--ink:#e8eef7;--muted:#93a1b5;--line:#1d2940;--green:#2ed3a3;--red:#f0556a;--blue:#5fa8ff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  .wrap{max-width:1000px;margin:0 auto;padding:40px 24px 80px}
  h1{font-size:23px;margin:0 0 4px}
  .sub{color:var(--muted);font-size:13px;margin-bottom:24px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:28px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
  .card b{display:block;font-size:26px}
  .card span{font-size:12px;color:var(--muted)}
  .card.g b{color:var(--green)} .card.r b{color:var(--red)} .card.b b{color:var(--blue)}
  details{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:8px;overflow:hidden}
  summary{cursor:pointer;padding:11px 14px;display:flex;align-items:center;gap:10px;font-size:13px;user-select:none}
  summary code{color:#8fd0ff;font-size:12.5px}
  summary::-webkit-details-marker{display:none}
  .cnt{margin-left:auto;color:var(--muted);font-size:12px}
  .fail{color:var(--red)}
  .dot{width:9px;height:9px;border-radius:50%;flex:none}
  .dot.g{background:var(--green)} .dot.r{background:var(--red)}
  table{width:100%;border-collapse:collapse;font-size:13px;border-top:1px solid var(--line)}
  td{padding:6px 14px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top}
  td.s{width:22px;color:var(--green);font-weight:700}
  tr.bad td.s{color:var(--red)}
  .suite{color:var(--muted)}
  td.d{width:70px;text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
  a{color:var(--blue)}
  footer{margin-top:26px;color:var(--muted);font-size:12px}
</style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ Kedayam — Test Results</h1>
  <div class="sub">Generated ${generated} · <a href="STATUS.html">← back to STATUS</a></div>
  <div class="cards">
    <div class="card ${j.numFailedTests ? "r" : "g"}"><b>${j.numTotalTests}</b><span>total tests</span></div>
    <div class="card g"><b>${j.numPassedTests}</b><span>passed</span></div>
    <div class="card ${j.numFailedTests ? "r" : ""}"><b>${j.numFailedTests}</b><span>failed</span></div>
    <div class="card b"><b>${files.length}</b><span>test files</span></div>
    <div class="card"><b>${passRate}%</b><span>pass rate</span></div>
    <div class="card"><b>${(totalDuration / 1000).toFixed(1)}s</b><span>duration</span></div>
  </div>
  ${fileSections}
  <footer>Regenerate with <code>bun run test:report</code>. Unit/redteam/compat suite (vitest); end-to-end Playwright tests run separately in CI.</footer>
</div>
</body>
</html>
`;

writeFileSync(OUT, html);
console.log(
  `[test-report] wrote ${OUT} — ${j.numPassedTests}/${j.numTotalTests} passed in ${files.length} files.`,
);
process.exit(j.numFailedTests ? 1 : 0);
