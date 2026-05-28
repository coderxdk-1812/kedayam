// Kedayam — Explainability.
//
// Wraps a raw trust-engine verdict into a structured, human-readable
// "why we said what we said" payload for the popup and warning UIs.
//
// Stable shape (UI code relies on these field names):
//
//   {
//     verdict, trustScore, phishingConfidence, cloneConfidence,
//     triggeredRules:   [ruleId, ...],         // ordered by severity
//     contributingTrust:[{id,title,points}],
//     contributingRisks:[{id,title,points,severity, plain}],
//     headline,         // 1-sentence summary (technical-leaning)
//     summary,          // plain-language paragraph ("what this means")
//     recommendation,   // plain-language next step ("what to do")
//     bullets,          // 2-4 plain-language phrases
//   }
//
// Design rule: every user-facing string in here MUST be readable by a
// non-technical user. No jargon ("CSP", "OAuth issuer", "eTLD+1"),
// no rule IDs, no scary words ("HACKER", "DANGER"). Calm, concrete.

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Bound on every user-facing string we emit. Long, run-on sentences are a
// readability tax and a place where internal jargon can leak through.
const MAX_USER_STR = 220;

// Internal terms that should never appear in user-facing text. We strip
// risks/rules whose only available wording is one of these (or contains
// raw rule-id syntax like "csp-downgrade"). Diagnostics still keep the raw
// IDs internally — this only governs what the popup shows.
// Match acronyms, OR identifier-shaped tokens with 3+ hyphen segments
// (e.g. "auth-flow-anomaly", "cross-origin-credential-post"). Two-segment
// hyphenated English ("sign-in", "two-factor", "well-known", "password-reset")
// is NOT considered jargon.
const JARGON_RE =
  /\b(CSP|OAuth issuer|eTLD\+1|JWT|XSS|CSRF|MITM|AiTM|SAML|JOSE|HSTS|TLS|CORS|PKCE)\b|\b[a-z]+(?:-[a-z]+){2,}\b/;

// Plain-language translations for the signal IDs the engine emits.
// Keep these short, concrete, and in second person where useful. No jargon,
// no acronyms, no rule IDs — these strings go straight to non-technical users.
const PLAIN_BY_SIGNAL_ID = Object.freeze({
  "lookalike":
    "The web address looks almost identical to a well-known site, but it isn't the real one.",
  "credential-form":
    "This page is asking for your password, and we can't confirm who actually runs it.",
  "credential-form-trusted":
    "This page asks for a password, and it's hosted on a site we recognize.",
  "credential-relay":
    "If you signed in here, your username and password would be sent to a different website.",
  "external-form-post":
    "This login form would send your details to a different website than the one you're on.",
  "oauth-token-drift":
    "The sign-in is redirecting through a place that doesn't match the service you started with.",
  "oauth-impersonation":
    "A 'sign in with' button on this page goes somewhere that isn't the real provider.",
  "mfa-only-unknown":
    "It's asking only for a one-time security code, on a site we can't verify — a common trick to capture codes.",
  "brand-impersonation":
    "This page uses the name and look of a well-known brand, but it isn't hosted by that brand.",
  "brand-keyword-mismatch":
    "The page talks about a well-known brand, but it isn't hosted by that brand.",
  "iframe-origin-swap":
    "Part of this page was quietly replaced with content from another site after it loaded.",
  "iframe-credential-form":
    "The login box on this page is loaded from a different website than the one you visited.",
  "iframe-login":
    "The sign-in here happens inside a frame that doesn't match the page address.",
  "csp-downgrade":
    "This login page is missing the standard safety protections real login pages normally have.",
  "form-javascript":
    "The login form sends your details through a script instead of the normal way, which makes it harder to verify where they go.",
  "hidden-login-fields":
    "The login form contains hidden fields a normal sign-in wouldn't need.",
  "domain-spoofing":
    "The web address is dressed up to look like a different, well-known site.",
  "idn-risk-cap":
    "The web address uses look-alike letters from other alphabets to imitate a real site.",
  "auth-keyword":
    "Words like 'login' or 'verify' appear in the web address itself — a common trick on fake pages.",
  "no-https":
    "The connection to this site isn't encrypted, so anything you type could be read by others on the network.",
  "userinfo":
    "The web address contains a username before the site name — a trick used to disguise where you really are.",
  "ip-host":
    "This page is hosted on a bare numeric address instead of a normal website name.",
  "long-redirects":
    "You were bounced through many hops before landing here — unusual for a normal site.",
  "cross-domain-redirects":
    "You were sent across several different websites before landing here.",
  "gsb":
    "Google Safe Browsing has flagged this address.",
  "vt":
    "Multiple security vendors have flagged this address.",
  "clone":
    "This page looks like a copy of a real, well-known site.",
  "auth-risk":
    "The sign-in setup here has some unusual aspects.",
  "https-trust":
    "The connection to this site is encrypted.",
  "known-reputable":
    "This is a well-known, established website.",
  "trusted-provider":
    "This is a recognized sign-in provider.",
  "allowlist":
    "This site is on your trusted list.",
  "allowlist-trust":
    "This site is on your trusted list.",
  "safelisted":
    "This site is on your trusted list.",
  "learned-safe":
    "You've used this site safely before.",
  "learned-safe-trust":
    "You've used this site safely before.",
  "no-auth-risk":
    "We didn't see any sign-in trickery on this page.",
  "established-domain":
    "This website has been around for a long time.",
  "security-context":
    "This page looks like it's discussing security, not performing a sign-in.",
});

// Plain-language summaries for arbitration rule IDs. Falls back to a sanitized
// version of rule.reason if unknown; never falls back to the raw id.
const PLAIN_BY_RULE_ID = Object.freeze({
  "lookalike-creds":
    "The web address copies a famous brand and is asking you to log in.",
  "unknown-login":
    "There's a login form here, but we can't verify who runs this site.",
  "credential-relay":
    "Your sign-in would be forwarded somewhere it shouldn't go.",
  "external-form-post":
    "The login form would send your details to a different website.",
  "oauth-token-drift":
    "The sign-in is redirecting through an unexpected place.",
});

/**
 * @param {object} verdict — output of trustEngine.evaluateUrl
 */
export function explainVerdict(verdict) {
  if (!verdict || typeof verdict !== "object") {
    return emptyExplanation();
  }

  const fired = (verdict.signals || []).filter((s) => (s.contribution ?? 0) < 0);
  const trust = (verdict.trustAdds || []);
  const rules = (verdict.arbitration?.rules || []);

  const triggeredRules = rules
    .slice()
    .sort((a, b) => (a.cap ?? 100) - (b.cap ?? 100))
    .map((r) => r.id);

  const contributingRisks = fired
    .slice()
    .sort((a, b) =>
      (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0) ||
      a.contribution - b.contribution)
    .slice(0, 5)
    .map((s) => ({
      id: s.id, title: s.title, severity: s.severity,
      points: s.contribution, detail: s.detail || "",
      plain: friendlyPhrase(PLAIN_BY_SIGNAL_ID[s.id], s.title),
    }));

  const contributingTrust = trust.slice(0, 5).map((t) => ({
    id: t.id, title: t.title, points: t.contribution, detail: t.detail || "",
    plain: friendlyPhrase(PLAIN_BY_SIGNAL_ID[t.id], t.title),
  }));

  const headline = clamp(buildHeadline(verdict, contributingRisks));
  const summary = clamp(buildSummary(verdict, contributingRisks));
  const recommendation = clamp(buildRecommendation(verdict));
  const bullets = buildBullets(verdict, contributingRisks, rules)
    .map(clamp).filter(Boolean);

  return {
    verdict: verdict.status,
    trustScore: verdict.score,
    phishingConfidence: verdict.phishingConfidence ?? 0,
    cloneConfidence: verdict.cloneConfidence ?? 0,
    triggeredRules,
    contributingTrust,
    contributingRisks,
    headline,
    summary,
    recommendation,
    bullets,
    evaluatedAt: verdict.evaluatedAt || Date.now(),
  };
}

function buildHeadline(v, risks) {
  const host = v.host || "This page";
  if (v.status === "dangerous") {
    // Tests assert this string contains "dangerous" — keep the word.
    const r = risks[0]?.plain || "we found several strong warning signs";
    return `${host} looks dangerous — ${lower(r)}`;
  }
  if (v.status === "suspicious") {
    const r = risks[0]?.plain || "a few things here don't add up";
    return `${host} doesn't look quite right — ${lower(r)}`;
  }
  return `${host} looks safe.`;
}

function buildSummary(v, risks) {
  if (v.status === "dangerous") {
    if (risks.length >= 2) {
      return "We found several strong signs that this page is trying to steal information. Don't enter any passwords, codes, or personal details here.";
    }
    return "We found a strong sign that this page is trying to steal information. Don't enter any passwords, codes, or personal details here.";
  }
  if (v.status === "suspicious") {
    return "Some things on this page don't match what a real, trustworthy site usually looks like. Be careful before signing in or sharing personal information.";
  }
  return "We didn't find any phishing or impersonation warning signs on this page.";
}

function buildRecommendation(v) {
  if (v.status === "dangerous") {
    return "Close this tab. If you got here from a link in an email or message, go directly to the real website by typing the address yourself.";
  }
  if (v.status === "suspicious") {
    return "If you weren't expecting to land here, leave the page. Only continue if you arrived by typing the address yourself or you know the site well.";
  }
  return "You can continue normally. Still, only share information you'd be comfortable sharing.";
}

function buildBullets(v, risks, rules) {
  const out = [];
  const seen = new Set();
  for (const r of risks.slice(0, 3)) {
    const text = r.plain;
    if (text && !seen.has(text)) { out.push(text); seen.add(text); }
  }
  for (const r of rules) {
    if (out.length >= 4) break;
    // Never fall back to the raw rule id — only a curated phrase or a
    // sanitized .reason that doesn't read like internal jargon.
    const text = PLAIN_BY_RULE_ID[r.id] || friendlyPhrase(null, r.reason);
    if (text && !seen.has(text)) { out.push(text); seen.add(text); }
  }
  if (!out.length && v.status === "safe") {
    out.push("No phishing or impersonation warning signs.");
  }
  return out;
}

// Pick a user-facing phrase. Prefer a curated plain-English version; only
// fall back to the raw title/reason if it looks readable. A "raw" string
// that contains a rule-id shape ("auth-flow-anomaly") or a known acronym
// is rejected in favor of a generic, calm description.
function friendlyPhrase(curated, raw) {
  const c = (curated || "").trim();
  if (c) return c;
  const r = (raw || "").trim();
  if (!r) return "";
  if (JARGON_RE.test(r)) {
    return "Something about this page doesn't match what we'd expect from a trustworthy site.";
  }
  return r;
}

function clamp(s) {
  if (!s) return s;
  if (s.length <= MAX_USER_STR) return s;
  return s.slice(0, MAX_USER_STR - 1).trimEnd() + "…";
}

function lower(s) {
  if (!s) return s;
  // Lowercase the first letter so the sentence flows after the em dash,
  // but keep proper nouns (e.g. "Microsoft") intact.
  return s.charAt(0).toLowerCase() + s.slice(1);
}

function emptyExplanation() {
  return {
    verdict: "suspicious", trustScore: 50,
    phishingConfidence: 0, cloneConfidence: 0,
    triggeredRules: [], contributingTrust: [], contributingRisks: [],
    headline: "We couldn't finish checking this page.",
    summary: "Kedayam wasn't able to evaluate this page. Treat it with normal caution until you can rescan.",
    recommendation: "Try reloading the page or clicking Rescan.",
    bullets: [],
    evaluatedAt: Date.now(),
  };
}
