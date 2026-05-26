import { accessSync, constants, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, normalize } from 'node:path';

const root = process.argv[2] || 'extension';
const manifestPath = join(root, 'manifest.json');
const errors = [];
const warnings = [];

function exists(rel) {
  const full = join(root, rel);
  try {
    accessSync(full, constants.R_OK);
    const size = statSync(full).size;
    if (size === 0) errors.push(`${rel} exists but is empty`);
    return size > 0;
  } catch {
    errors.push(`Missing referenced file: ${rel}`);
    return false;
  }
}
function validRelative(rel, label) {
  if (!rel || typeof rel !== 'string') return errors.push(`${label} must be a string path`);
  if (rel.startsWith('/') || rel.includes('..') || normalize(rel).startsWith('..')) errors.push(`${label} must stay inside the extension package: ${rel}`);
  exists(rel);
}
function iconMap(map, label) {
  for (const size of ['16', '32', '48', '128']) {
    if (!map?.[size]) errors.push(`${label} is missing ${size}px icon`);
    else {
      validRelative(map[size], `${label}.${size}`);
      if (!map[size].endsWith('.png')) errors.push(`${label}.${size} must be a PNG file, not ${map[size]}`);
    }
  }
}

let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
} catch (error) {
  console.error(`Could not parse ${manifestPath}:`, error.message);
  process.exit(1);
}

if (manifest.manifest_version !== 3) errors.push('manifest_version must be 3');
if (!manifest.name || manifest.name.length > 75) errors.push('name is required and must be <= 75 characters');
if (!/^\d+\.\d+\.\d+(\.\d+)?$/.test(manifest.version || '')) errors.push('version must be Chrome-compatible semver');
if (!manifest.description || manifest.description.length > 132) warnings.push('description should be present and <= 132 characters for the Chrome Web Store');

iconMap(manifest.icons, 'icons');
iconMap(manifest.action?.default_icon, 'action.default_icon');
validRelative(manifest.action?.default_popup, 'action.default_popup');
validRelative(manifest.options_page, 'options_page');
validRelative(manifest.background?.service_worker, 'background.service_worker');
if (manifest.background?.type !== 'module') errors.push('background.type must be "module" for this ES module service worker');

for (const [i, cs] of (manifest.content_scripts || []).entries()) {
  for (const js of cs.js || []) validRelative(js, `content_scripts[${i}].js`);
  for (const css of cs.css || []) validRelative(css, `content_scripts[${i}].css`);
  if (!Array.isArray(cs.matches) || !cs.matches.length) errors.push(`content_scripts[${i}].matches is required`);
}

const allowedPermissions = new Set(['activeTab', 'storage', 'tabs', 'notifications', 'webNavigation', 'webRequest']);
for (const permission of manifest.permissions || []) {
  if (!allowedPermissions.has(permission)) warnings.push(`Review permission: ${permission}`);
}

const filesToScan = [manifestPath, ...[manifest.background?.service_worker, manifest.action?.default_popup, manifest.options_page].filter(Boolean).map((p) => join(root, p))];
for (const file of filesToScan) {
  const text = readFileSync(file, 'utf8');
  if (/icon\.svg/i.test(text)) errors.push(`${file} still references icon.svg`);
}

// ---- CSP / inline-script audit on every JS file under the extension ----
function walk(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith('.') || e.name === 'node_modules') continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}
const allFiles = walk(root);
const jsFiles = allFiles.filter((f) => /\.(js|mjs|html)$/i.test(f));
for (const file of jsFiles) {
  const text = readFileSync(file, 'utf8');
  // Forbid runtime-built inline scripts (textContent injection, eval, new Function).
  // We look for clear anti-patterns; benign matches like writing strings to
  // unrelated DOM nodes should not appear in extension code.
  const rx = [
    { re: /\bnew\s+Function\s*\(/g, msg: 'uses new Function() (CSP-violating eval)' },
    { re: /\beval\s*\(/g, msg: 'uses eval() (CSP-violating)' },
    { re: /document\.write\s*\(/g, msg: 'uses document.write (CSP-risky)' },
    { re: /\.textContent\s*=\s*[`'"][^`'"\n]*function/g, msg: 'looks like inline-script injection via textContent' },
    { re: /innerHTML\s*=\s*[`'"][^`'"]*<script/gi, msg: 'injects <script> via innerHTML (CSP-violating)' },
  ];
  for (const { re, msg } of rx) {
    if (re.test(text)) errors.push(`${file}: ${msg}`);
  }
}

// ---- web_accessible_resources files exist ----
for (const grp of manifest.web_accessible_resources || []) {
  for (const r of grp.resources || []) validRelative(r, `web_accessible_resources:${r}`);
}

if (warnings.length) console.warn(warnings.map((w) => `Warning: ${w}`).join('\n'));
if (errors.length) {
  console.error(errors.map((e) => `Error: ${e}`).join('\n'));
  process.exit(1);
}
console.log(`Kedayam extension valid. Checked manifest, ${jsFiles.length} JS/HTML files for CSP violations, and ${manifest.web_accessible_resources?.length || 0} WAR groups.`);
