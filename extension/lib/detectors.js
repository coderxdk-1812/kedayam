// Local sensitive-data detectors. Pure functions. No data leaves the browser.

const PATTERNS = {
  email: {
    label: "Email address",
    severity: "low",
    region: "global",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  phoneIN: {
    label: "Indian phone number",
    severity: "medium",
    region: "india",
    regex: /(?:\+?91[\s-]?)?[6-9]\d{9}\b/g,
  },
  phoneUS: {
    label: "US phone number",
    severity: "medium",
    region: "us",
    regex: /\b(?:\+?1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
  },
  aadhaar: {
    label: "Aadhaar number",
    severity: "critical",
    region: "india",
    regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
  },
  pan: {
    label: "PAN card number",
    severity: "high",
    region: "india",
    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
  },
  ssn: {
    label: "US SSN",
    severity: "critical",
    region: "us",
    regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  iban: {
    label: "IBAN",
    severity: "high",
    region: "eu",
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g,
  },
  creditCard: {
    label: "Credit card number",
    severity: "critical",
    region: "global",
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    validate: (m) => luhn(m.replace(/\D/g, "")),
  },
  awsKey: {
    label: "AWS access key",
    severity: "critical",
    region: "global",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  awsSecret: {
    label: "AWS secret key",
    severity: "critical",
    region: "global",
    regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    requiresContext: /aws|secret|amazon/i,
  },
  ghToken: {
    label: "GitHub token",
    severity: "critical",
    region: "global",
    regex: /\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/g,
  },
  slackToken: {
    label: "Slack token",
    severity: "critical",
    region: "global",
    regex: /\bxox[abps]-[A-Za-z0-9-]{10,}\b/g,
  },
  jwt: {
    label: "JWT",
    severity: "high",
    region: "global",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  privateKey: {
    label: "Private key block",
    severity: "critical",
    region: "global",
    regex: /-----BEGIN ((RSA|EC|OPENSSH|PGP) )?PRIVATE KEY-----/g,
  },
  genericApiKey: {
    label: "Generic API key",
    severity: "high",
    region: "global",
    regex: /\b(?:api[_-]?key|secret|token)["':=\s]+["']?[A-Za-z0-9_\-]{24,}/gi,
  },
};

function luhn(num) {
  if (num.length < 13 || num.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let n = parseInt(num[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let H = 0;
  for (const c in freq) {
    const p = freq[c] / str.length;
    H -= p * Math.log2(p);
  }
  return H;
}

export function highEntropySecrets(text, { minLen = 24, threshold = 4.2 } = {}) {
  const out = [];
  const tokens = text.match(/[A-Za-z0-9+/_=-]{20,}/g) || [];
  for (const t of tokens) {
    if (t.length < minLen) continue;
    if (shannonEntropy(t) >= threshold) {
      out.push({ kind: "highEntropy", label: "High-entropy secret", severity: "medium", value: redact(t) });
    }
  }
  return out;
}

export function scanText(text, { regions } = { regions: { india: true, us: true, eu: true, global: true } }) {
  if (!text || typeof text !== "string") return [];
  const findings = [];
  for (const [kind, def] of Object.entries(PATTERNS)) {
    if (def.region !== "global" && !regions?.[def.region]) continue;
    if (def.requiresContext && !def.requiresContext.test(text)) continue;
    const matches = text.match(def.regex) || [];
    for (const raw of matches) {
      if (def.validate && !def.validate(raw)) continue;
      findings.push({
        kind,
        label: def.label,
        severity: def.severity,
        value: redact(raw),
      });
      if (findings.length > 50) break;
    }
  }
  findings.push(...highEntropySecrets(text));
  return dedupe(findings);
}

export function highestSeverity(findings) {
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  return findings.reduce((acc, f) => (order[f.severity] > order[acc] ? f.severity : acc), "low");
}

function redact(v) {
  if (v.length <= 6) return "•".repeat(v.length);
  return v.slice(0, 2) + "•".repeat(Math.min(v.length - 4, 10)) + v.slice(-2);
}

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const k = `${f.kind}:${f.value}`;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });
}