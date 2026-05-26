// Kedayam — Explainability.
//
// Wraps a raw trust-engine verdict into a structured, human-readable
// "why we said what we said" payload for the popup and warning UIs.
//
// The shape is stable — UI code can rely on these field names:
//
//   {
//     verdict, trustScore, phishingConfidence, cloneConfidence,
//     triggeredRules:   [ruleId, ...],         // ordered by severity
//     contributingTrust:[{id,title,points}],
//     contributingRisks:[{id,title,points,severity}],
//     headline,                                // 1-sentence summary
//     bullets,                                 // 2-4 bullet phrases
//   }

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

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
    }));

  const contributingTrust = trust.slice(0, 5).map((t) => ({
    id: t.id, title: t.title, points: t.contribution, detail: t.detail || "",
  }));

  const headline = buildHeadline(verdict, contributingRisks);
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
    bullets,
    evaluatedAt: verdict.evaluatedAt || Date.now(),
  };
}

function buildHeadline(v, risks) {
  if (v.status === "dangerous") {
    const reason = risks[0]?.title?.toLowerCase() || "multiple high-risk signals";
    return `${v.host || "This page"} is dangerous — ${reason}.`;
  }
  if (v.status === "suspicious") {
    const reason = risks[0]?.title?.toLowerCase() || "unverified authentication workflow";
    return `${v.host || "This page"} looks unusual — ${reason}.`;
  }
  return `${v.host || "This page"} looks safe (trust ${v.score}/100).`;
}

function buildBullets(v, risks, rules) {
  const out = [];
  for (const r of risks.slice(0, 3)) {
    out.push(r.detail ? `${r.title} — ${r.detail}` : r.title);
  }
  for (const r of rules.slice(0, 2)) {
    if (out.length >= 4) break;
    if (r.reason) out.push(`Rule: ${r.reason}`);
  }
  if (!out.length && v.status === "safe") {
    out.push("No phishing or impersonation signals fired.");
  }
  return out;
}

function emptyExplanation() {
  return {
    verdict: "suspicious", trustScore: 50,
    phishingConfidence: 0, cloneConfidence: 0,
    triggeredRules: [], contributingTrust: [], contributingRisks: [],
    headline: "Verdict unavailable.", bullets: [],
    evaluatedAt: Date.now(),
  };
}
