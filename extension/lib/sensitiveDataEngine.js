// Kedayam — Sensitive Data Engine
//
// Deterministic, ephemeral, in-memory classifier for credentials and PII.
// Pipeline:
//   normalize → tokenize → classify → validate → entropy → context score
//   → suppression rules → verdict
//
// Privacy invariants (enforced by code review, not just docs):
//   • No raw value is ever stored, logged, or returned to callers.
//   • Findings carry redacted previews only, plus structural metadata.
//   • Suppression heuristics aggressively kill placeholder / example /
//     tutorial / mock data so we never warn on `sk_live_xxxxxxxx` from a
//     blog post.
//
// This module is dependency-free so it can be loaded into content scripts,
// service workers, and tests.

// ---------- Pattern catalog ----------
//
// Each pattern has:
//   id         stable identifier
//   label      human display name
//   severity   low | medium | high | critical
//   regex      detection pattern (g flag)
//   validate   optional checksum / structural validator
//   minEntropy optional minimum Shannon entropy for the match body
//   prefixOf   optional set of prefixes that, if present, raise confidence
//   contextHints  regex of nearby tokens (within ~80 chars) that confirm intent
//   negative   regex of tokens that *suppress* the match (placeholder words)
//
const PATTERNS = [
  // --- Cloud / IaaS keys ---
  { id: "aws_access_key", label: "AWS access key", severity: "critical",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, confidence: 0.98 },
  { id: "aws_secret_key", label: "AWS secret key", severity: "critical",
    regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    minEntropy: 4.0,
    contextHints: /aws|secret|amazon|amzn/i, confidence: 0.7 },
  { id: "gcp_api_key", label: "Google Cloud API key", severity: "critical",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, confidence: 0.97 },
  { id: "gcp_service_account", label: "GCP service account JSON",
    severity: "critical",
    regex: /"type"\s*:\s*"service_account"/g, confidence: 0.95 },
  { id: "azure_sas", label: "Azure SAS token", severity: "high",
    regex: /\b(sv|sig)=[A-Za-z0-9%]{20,}/g,
    contextHints: /azure|blob|storage|core\.windows\.net/i, confidence: 0.7 },

  // --- VCS / SaaS tokens ---
  { id: "github_classic", label: "GitHub personal token", severity: "critical",
    regex: /\bghp_[A-Za-z0-9]{36}\b/g, confidence: 0.99 },
  { id: "github_fine", label: "GitHub fine-grained token", severity: "critical",
    regex: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, confidence: 0.99 },
  { id: "gitlab_token", label: "GitLab token", severity: "critical",
    regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, confidence: 0.97 },
  { id: "slack_token", label: "Slack token", severity: "critical",
    regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, confidence: 0.97 },
  { id: "stripe_secret", label: "Stripe secret key", severity: "critical",
    regex: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{24,}\b/g, confidence: 0.99 },
  { id: "openai_key", label: "OpenAI / Lovable AI key", severity: "critical",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g, confidence: 0.95 },
  { id: "anthropic_key", label: "Anthropic API key", severity: "critical",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, confidence: 0.98 },

  // --- Cryptography ---
  { id: "private_key_block", label: "Private key block", severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    confidence: 1 },
  { id: "ssh_authorized", label: "SSH public key (review)", severity: "low",
    regex: /\bssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/=]{40,}/g, confidence: 0.8 },
  { id: "jwt", label: "JWT", severity: "high",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    confidence: 0.9 },
  { id: "crypto_seed", label: "Crypto seed phrase", severity: "critical",
    // 12 / 15 / 18 / 21 / 24 lowercase words separated by single spaces
    regex: /\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b/g,
    validate: (s) => looksLikeMnemonic(s), confidence: 0.95 },

  // --- Financial ---
  { id: "credit_card", label: "Credit / debit card", severity: "critical",
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    validate: (s) => luhn(s.replace(/\D/g, "")),
    negative: /\b(test|sample|example|dummy|placeholder|4242[\s-]?4242|0000[\s-]?0000)\b/i,
    confidence: 0.92 },
  { id: "iban", label: "IBAN", severity: "high",
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g,
    validate: (s) => ibanChecksum(s), confidence: 0.92 },
  { id: "swift", label: "SWIFT / BIC", severity: "medium",
    regex: /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g,
    contextHints: /swift|bic|bank|wire/i, confidence: 0.7 },

  // --- Government IDs ---
  { id: "ssn", label: "US SSN", severity: "critical",
    regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    confidence: 0.95 },
  { id: "aadhaar", label: "Aadhaar", severity: "critical",
    regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    validate: (s) => verhoeffAadhaar(s.replace(/\D/g, "")),
    confidence: 0.9 },
  { id: "pan", label: "PAN", severity: "high",
    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g, confidence: 0.9 },

  // --- MFA / recovery ---
  { id: "mfa_backup_code", label: "MFA backup code", severity: "high",
    regex: /\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b/g,
    contextHints: /backup|recovery|two[- ]?factor|2fa|mfa|authenticator/i,
    confidence: 0.85 },
];

// Tokens that imply the surrounding text is documentation / a tutorial /
// a placeholder example — anything that should NOT trigger.
const PLACEHOLDER_TOKENS = [
  "your_", "<your", "example", "placeholder", "xxxxxxxx", "lorem",
  "ipsum", "abc123", "password123", "changeme", "demo_", "sample_",
  "fake_", "test_only", "dotenv", "process.env.",
];

// Phrases that indicate the surrounding text is a docs / API tutorial.
// Used as a global suppression multiplier.
const DOC_CONTEXT = /\b(curl\s+-X|fetch\(|axios\.|require\(|import\s+\{|getenv|process\.env|export\s+(const|let|var)|api\s+reference|see\s+docs|getting started|tutorial)\b/i;

// ---------- Public API ----------

/**
 * Analyze a payload ephemerally. Caller must discard `text` immediately after
 * receiving the verdict.
 *
 * @param {string} text
 * @param {{ targetHost?: string, isTrustedDestination?: boolean }} [meta]
 * @returns {{
 *   findings: Array<{
 *     id: string, label: string, severity: 'low'|'medium'|'high'|'critical',
 *     confidence: number, redacted: string, offset: number,
 *     suppressed: boolean, suppressionReason?: string
 *   }>,
 *   detectedTypes: string[],
 *   riskScore: number,           // 0..1
 *   riskLevel: 'none'|'low'|'medium'|'high'|'critical',
 *   suppressed: number,
 * }}
 */
export function analyzeSensitivePayload(text, meta = {}) {
  if (typeof text !== "string" || !text || text.length > 200_000) {
    return emptyVerdict();
  }
  const normalized = normalize(text);
  const docContext = DOC_CONTEXT.test(normalized);
  const findings = [];

  for (const p of PATTERNS) {
    p.regex.lastIndex = 0;
    let m;
    let count = 0;
    while ((m = p.regex.exec(normalized)) && count < 25) {
      count++;
      const raw = m[0];
      const offset = m.index;
      const window = sliceWindow(normalized, offset, raw.length);

      // Structural validation
      if (p.validate && !p.validate(raw)) continue;
      if (p.minEntropy && shannonEntropy(raw) < p.minEntropy) continue;
      if (p.contextHints && !p.contextHints.test(window)) continue;

      // Suppression
      let confidence = p.confidence ?? 0.8;
      let suppressed = false;
      let reason;

      if (p.negative && p.negative.test(window)) {
        suppressed = true; reason = "negative-context";
      }
      if (!suppressed && hasPlaceholderToken(window)) {
        suppressed = true; reason = "placeholder-token";
      }
      if (!suppressed && looksLikeMockNumber(raw)) {
        suppressed = true; reason = "mock-number";
      }
      if (!suppressed && docContext && p.severity !== "critical") {
        // Soften but don't kill: docs often contain real keys by mistake.
        confidence *= 0.6;
        if (confidence < 0.5) { suppressed = true; reason = "doc-context"; }
      }
      if (!suppressed && p.contextHints) {
        // Strong-context patterns gain confidence when the hint is close.
        const proximity = nearestHitDistance(window, p.contextHints);
        if (proximity >= 0 && proximity < 30) confidence = Math.min(1, confidence + 0.1);
      }

      findings.push({
        id: p.id, label: p.label, severity: p.severity,
        confidence: round2(confidence),
        redacted: redact(raw), offset,
        suppressed, suppressionReason: reason,
      });
    }
  }

  // Entropy-only fallback for unknown long tokens (last-resort).
  for (const tok of (normalized.match(/[A-Za-z0-9+/_=-]{32,}/g) || []).slice(0, 40)) {
    if (findings.some((f) => normalized.indexOf(tok) === f.offset)) continue;
    const H = shannonEntropy(tok);
    if (H < 4.5) continue;
    if (hasPlaceholderToken(tok)) continue;
    findings.push({
      id: "entropy_blob", label: "High-entropy secret-like blob",
      severity: "medium", confidence: round2(Math.min(0.85, (H - 4.5) * 0.5 + 0.55)),
      redacted: redact(tok), offset: normalized.indexOf(tok),
      suppressed: false,
    });
  }

  const live = findings.filter((f) => !f.suppressed);
  const detectedTypes = [...new Set(live.map((f) => f.id))];
  const riskScore = computeRisk(live, meta);
  const riskLevel = riskLevelFor(riskScore, live);

  return {
    findings,
    detectedTypes,
    riskScore: round2(riskScore),
    riskLevel,
    suppressed: findings.length - live.length,
  };
}

// ---------- Pure helpers ----------

export function shannonEntropy(s) {
  if (!s) return 0;
  const f = Object.create(null);
  for (const c of s) f[c] = (f[c] || 0) + 1;
  let H = 0;
  for (const c in f) { const p = f[c] / s.length; H -= p * Math.log2(p); }
  return H;
}

export function luhn(num) {
  if (!/^\d+$/.test(num) || num.length < 13 || num.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let n = +num[i]; if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

// ISO 13616 IBAN mod-97 check.
export function ibanChecksum(s) {
  const clean = s.replace(/\s+/g, "").toUpperCase();
  if (clean.length < 15 || clean.length > 34) return false;
  const rearr = clean.slice(4) + clean.slice(0, 4);
  let acc = "";
  for (const c of rearr) {
    acc += /[A-Z]/.test(c) ? (c.charCodeAt(0) - 55).toString() : c;
  }
  // Big-number mod 97 in chunks.
  let rem = 0;
  for (let i = 0; i < acc.length; i += 7) {
    rem = parseInt(String(rem) + acc.slice(i, i + 7), 10) % 97;
  }
  return rem === 1;
}

// Aadhaar uses the Verhoeff checksum (12 digits).
const VERHOEFF_D = [
  [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
  [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
  [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
  [9,8,7,6,5,4,3,2,1,0]];
const VERHOEFF_P = [
  [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
  [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
  [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
export function verhoeffAadhaar(s) {
  if (!/^\d{12}$/.test(s)) return false;
  let c = 0;
  const digits = s.split("").reverse().map(Number);
  for (let i = 0; i < digits.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digits[i]]];
  }
  return c === 0;
}

// BIP-39-style word lists are large; we approximate by requiring all words
// be short lowercase a-z, no duplicates beyond a threshold (real seeds rarely
// repeat), and total entropy across the joined string above 3.4.
export function looksLikeMnemonic(s) {
  const words = s.trim().split(/\s+/);
  if (![12, 15, 18, 21, 24].includes(words.length)) return false;
  if (!words.every((w) => /^[a-z]{3,8}$/.test(w))) return false;
  const unique = new Set(words);
  if (unique.size < words.length * 0.7) return false; // too repetitive
  return shannonEntropy(words.join("")) > 3.4;
}

function normalize(s) { return s.normalize("NFKC"); }
function sliceWindow(s, offset, len) {
  const start = Math.max(0, offset - 80);
  const end = Math.min(s.length, offset + len + 80);
  return s.slice(start, end).toLowerCase();
}
function hasPlaceholderToken(s) {
  const lower = s.toLowerCase();
  return PLACEHOLDER_TOKENS.some((t) => lower.includes(t));
}
function looksLikeMockNumber(s) {
  const digits = s.replace(/\D/g, "");
  if (!digits) return false;
  // All same digit, classic test cards, sequential runs.
  if (/^(\d)\1+$/.test(digits)) return true;
  if (/^4242424242424242$/.test(digits)) return true;
  if (/^(0123456789|1234567890)/.test(digits)) return true;
  return false;
}
function nearestHitDistance(window, re) {
  const m = re.exec(window); re.lastIndex = 0;
  return m ? Math.abs(window.length / 2 - m.index) : -1;
}
function redact(v) {
  if (v.length <= 6) return "•".repeat(v.length);
  return v.slice(0, 2) + "•".repeat(Math.min(v.length - 4, 10)) + v.slice(-2);
}
function round2(n) { return Math.round(n * 100) / 100; }

function computeRisk(live, meta) {
  if (!live.length) return 0;
  const weights = { critical: 1, high: 0.7, medium: 0.4, low: 0.15 };
  let r = 0;
  for (const f of live) r = Math.max(r, weights[f.severity] * f.confidence);
  // Untrusted destination amplifies risk; trusted dampens it.
  if (meta?.isTrustedDestination === false) r = Math.min(1, r + 0.1);
  if (meta?.isTrustedDestination === true) r = Math.max(0, r - 0.2);
  return r;
}
function riskLevelFor(score, live) {
  if (!live.length) return "none";
  if (score >= 0.85) return "critical";
  if (score >= 0.6) return "high";
  if (score >= 0.35) return "medium";
  return "low";
}
function emptyVerdict() {
  return { findings: [], detectedTypes: [], riskScore: 0,
    riskLevel: "none", suppressed: 0 };
}

export const _internal = {
  PATTERNS, PLACEHOLDER_TOKENS, DOC_CONTEXT,
  hasPlaceholderToken, looksLikeMockNumber,
};
