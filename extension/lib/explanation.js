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

// Plain-language translations for the signal IDs the engine emits.
// Keep these short (one sentence), concrete, and second-person where useful.
const PLAIN_BY_SIGNAL_ID = Object.freeze({
  "lookalike":
    "The web address looks almost identical to a well-known site, but it isn't the real one.",
  "credential-form":
    "This page is asking for your password, and we can't confirm who actually runs it.",
  "credential-relay":
    "If you signed in here, your username and password would be sent to a different website.",
  "external-form-post":
    "The login form would send your details to a completely different website than the one shown in the address bar.",
  "oauth-token-drift":
    "The sign-in process is redirecting through a place that doesn't match the service you started with.",
  "mfa-only-unknown":
    "It's asking only for a one-time security code, on a site we can't verify — a common trick to capture codes.",
  "brand-keyword-mismatch":
    "The page talks about a well-known brand, but it isn't hosted by that brand.",
  "iframe-origin-swap":
    "Part of this page was quietly replaced with content from another site after it loaded.",
  "csp-downgrade":
    "This login page is missing the standard safety protections that real login pages normally have.",
  "https-trust":
    "The connection to this site is encrypted.",
  "safelisted":
    "This site is on your trusted list.",
});

// Plain-language summaries for arbitration rule IDs (the higher-level
// "why we capped the score" reasons). Falls back to rule.reason if unknown.
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
      plain: PLAIN_BY_SIGNAL_ID[s.id] || s.title,
    }));

  const contributingTrust = trust.slice(0, 5).map((t) => ({
    id: t.id, title: t.title, points: t.contribution, detail: t.detail || "",
    plain: PLAIN_BY_SIGNAL_ID[t.id] || t.title,
  }));

  const headline = buildHeadline(verdict, contributingRisks);
  const summary = buildSummary(verdict, contributingRisks);
  const recommendation = buildRecommendation(verdict);
  const bullets = buildBullets(verdict, contributingRisks, rules);

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
    const r = risks[0]?.plain || risks[0]?.title || "multiple strong warning signs";
    return `${host} looks dangerous — ${lower(r)}`;
  }
  if (v.status === "suspicious") {
    const r = risks[0]?.plain || risks[0]?.title || "a few things here don't add up";
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
    const text = r.plain || r.title;
    if (text && !seen.has(text)) { out.push(text); seen.add(text); }
  }
  for (const r of rules) {
    if (out.length >= 4) break;
    const text = PLAIN_BY_RULE_ID[r.id] || r.reason;
    if (text && !seen.has(text)) { out.push(text); seen.add(text); }
  }
  if (!out.length && v.status === "safe") {
    out.push("No phishing or impersonation warning signs.");
  }
  return out;
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
