// Kedayam — contextual dampening for security-research / educational pages.
//
// Purpose: reduce VISUAL / TEXTUAL false positives on legitimate pages that
// *discuss* phishing, host benign demo auth content, document OAuth flows,
// or analyze malware. These pages legitimately contain phishing keywords,
// fake login fragments, and brand mentions, but they are not themselves
// credential-harvesting pages.
//
// Strict scope:
//   • This module ONLY signals "the surrounding context looks educational
//     / analytical". It does NOT trust the page, does NOT modify
//     arbitration rules, does NOT touch behavioral signals.
//   • Behavioral evidence (external POST, cross-origin creds, OAuth spoof,
//     MFA harvest, threat-intel hits, auth-flow anomalies) bypasses this
//     module entirely — those still escalate normally.
//
// Output: a numeric dampening factor in [0, 1] and an audit trail. The
// trust engine applies dampening pre-arbitration by softening the
// confidence of visual-only inputs (lookalike / clone / brand-text).

const RESEARCH_TERMS = [
  "phishing analysis", "phishing kit", "phishing campaign", "phishing sample",
  "phishing url", "threat intelligence", "ioc", "indicator of compromise",
  "indicators of compromise", "malware sample", "malware analysis",
  "sandbox analysis", "detonation", "url scan", "url analysis",
  "scan report", "submission report", "submitted url", "analysis report",
  "virustotal", "urlscan", "phishtank", "any.run", "anyrun",
  "hybrid-analysis", "hybrid analysis", "joe sandbox", "joesandbox",
  "tria.ge", "triage report", "abuse.ch", "openphish", "alienvault",
  "otx pulse", "misp", "yara rule", "sigma rule",
];

const EDU_TERMS = [
  "tutorial", "documentation", "docs", "example", "code example",
  "demo", "demonstration", "sample app", "getting started", "guide",
  "walkthrough", "reference", "developer guide", "api reference",
  "training", "course", "lesson", "workshop", "lab exercise",
  "awareness", "simulation exercise", "phishing awareness",
  "security training", "security awareness", "educational",
];

const AUTH_DOC_TERMS = [
  "oauth 2.0", "oauth2", "openid connect", "oidc",
  "authorization code flow", "authorization code grant",
  "implicit flow", "client credentials", "device code flow",
  "pkce", "redirect_uri", "client_id", "client_secret",
  "access token", "refresh token", "id_token", "scopes",
  "saml assertion", "saml response", "jwks", "well-known/openid-configuration",
];

// Host fragments commonly belonging to security/analysis platforms,
// developer docs hubs, and educational content. NOT a safelist — these
// only feed the dampening score; behavioral evidence still escalates.
const RESEARCH_HOST_FRAGMENTS = [
  "virustotal.com", "urlscan.io", "phishtank.", "phishtank.org",
  "any.run", "app.any.run", "hybrid-analysis.com", "tria.ge",
  "joesandbox.com", "abuse.ch", "openphish.com", "alienvault.com",
  "otx.alienvault.com", "misp-project.org", "threatcrowd.org",
  "shodan.io", "censys.io", "greynoise.io", "abuseipdb.com",
];

const DOC_HOST_PREFIXES = [
  "docs.", "developer.", "developers.", "learn.", "help.",
  "support.", "guide.", "guides.", "tutorial.", "tutorials.",
];

const DOC_PATH_FRAGMENTS = [
  "/docs/", "/doc/", "/documentation/", "/developer/", "/developers/",
  "/learn/", "/tutorial", "/tutorials/", "/guide/", "/guides/",
  "/reference/", "/examples/", "/cookbook/", "/howto/",
];

function countMatches(haystack, needles) {
  if (!haystack) return 0;
  let n = 0;
  for (const t of needles) if (haystack.includes(t)) n++;
  return n;
}

/**
 * @param {{ host?: string, path?: string, pageContext?: any }} input
 * @returns {{ score:number, reasons:string[], buckets:Record<string,number> }}
 */
export function analyzeSecurityContext(input) {
  const out = { score: 0, reasons: [], buckets: {
    research: 0, education: 0, authDocs: 0, host: 0, path: 0,
  } };
  if (!input) return out;

  const host = (input.host || "").toLowerCase();
  const path = (input.path || "").toLowerCase();
  const pc = input.pageContext || {};
  const title = String(pc.title || "").toLowerCase();
  const text = String(pc.visibleText || "").toLowerCase().slice(0, 20000);
  const haystack = `${title}\n${text}`;

  // ---- text buckets ----
  const research = countMatches(haystack, RESEARCH_TERMS);
  const edu = countMatches(haystack, EDU_TERMS);
  const authDocs = countMatches(haystack, AUTH_DOC_TERMS);
  out.buckets.research = research;
  out.buckets.education = edu;
  out.buckets.authDocs = authDocs;

  if (research >= 2) {
    out.score += 0.45;
    out.reasons.push(`security/research vocabulary (${research} terms)`);
  } else if (research === 1) {
    out.score += 0.15;
  }
  if (edu >= 3) {
    out.score += 0.3;
    out.reasons.push(`educational/demo vocabulary (${edu} terms)`);
  } else if (edu >= 1) {
    out.score += 0.1;
  }
  if (authDocs >= 2) {
    out.score += 0.3;
    out.reasons.push(`auth-documentation vocabulary (${authDocs} terms)`);
  } else if (authDocs === 1) {
    out.score += 0.1;
  }

  // ---- host hints ----
  let hostHit = 0;
  for (const frag of RESEARCH_HOST_FRAGMENTS) {
    if (host.includes(frag)) { hostHit++; break; }
  }
  if (hostHit) {
    out.score += 0.45;
    out.buckets.host = 1;
    out.reasons.push("host is a known analysis / threat-intel platform");
  } else {
    for (const pref of DOC_HOST_PREFIXES) {
      if (host.startsWith(pref)) {
        out.score += 0.2;
        out.buckets.host = 1;
        out.reasons.push(`host prefix "${pref}" suggests documentation site`);
        break;
      }
    }
  }

  // ---- path hints ----
  for (const frag of DOC_PATH_FRAGMENTS) {
    if (path.includes(frag)) {
      out.score += 0.15;
      out.buckets.path = 1;
      out.reasons.push(`path contains documentation fragment "${frag.trim()}"`);
      break;
    }
  }

  // GitHub-style demo / sample / example repositories.
  if (/github\.(com|io)$/.test(host) &&
      /(demo|example|sample|tutorial|awareness|training|playground)/.test(path)) {
    out.score += 0.2;
    out.reasons.push("GitHub demo/example/training path");
  }

  // Clamp.
  if (out.score > 1) out.score = 1;
  if (out.score < 0) out.score = 0;
  out.score = Math.round(out.score * 100) / 100;
  return out;
}

// Threshold at or above which dampening applies.
export const SECURITY_CONTEXT_THRESHOLD = 0.6;

/**
 * Apply dampening factor to a confidence value.
 * dampening 0 → unchanged; dampening 1 → reduced by up to 80%.
 */
export function dampenConfidence(confidence, dampening) {
  const c = Number(confidence) || 0;
  const d = Math.max(0, Math.min(1, Number(dampening) || 0));
  return Math.max(0, c * (1 - d * 0.8));
}
