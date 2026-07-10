// Kedayam — Arbitration Trace (M5).
//
// Builds a verbose, local-only lineage object that explains *why* a verdict
// landed where it did. Strictly never transmitted; pure derivation from
// already-computed arbitration / decay / suspicion structures.

/**
 * @param {Object} args
 * @param {Object} args.arbitration  — output of arbitrate()
 * @param {Object} [args.decay]      — output of trustDecay()
 * @param {Object} [args.suspicion]  — output of deriveSuspicion()
 * @param {number} [args.score]
 * @param {number} [args.baselineScore]
 * @param {boolean} [args.trustedRoot]
 * @param {boolean} [args.behavioralEvidence]
 */
export function buildArbitrationTrace(args = {}) {
  const arb = args.arbitration || { rules: [] };
  const decay = args.decay || { delta: 0, anomalies: [] };
  const susp = args.suspicion || null;
  const rules = (arb.rules || []).map((r) => ({
    id: r.id,
    role: r.force ? "escalation" : r.cap != null && r.cap < 100 ? "cap" : "informational",
    cap: r.cap ?? null,
    force: r.force || null,
    reason: r.reason || "",
  }));
  const suppressedIds = arb.shadowSuppressed || [];
  const trustFloor = arb.trustFloor ?? null;

  // Lineage groups — rules that share an arbitration role.
  const escalations = rules.filter((r) => r.role === "escalation");
  const caps = rules.filter((r) => r.role === "cap");
  const informational = rules.filter((r) => r.role === "informational");

  return Object.freeze({
    version: 1,
    score: args.score ?? null,
    baselineScore: args.baselineScore ?? null,
    trustedRoot: !!args.trustedRoot,
    behavioralEvidence: !!args.behavioralEvidence,
    arbitration: { trustFloor, forceStatus: arb.forceStatus || null, cap: arb.cap ?? null },
    rules,
    suppressedIds,
    escalations,
    caps,
    informational,
    decay: {
      delta: decay.delta || 0,
      anomalies: decay.anomalies || [],
      floorOverride: decay.floorOverride ?? null,
    },
    suspicion: susp,
    explain: explainTrace({ rules, decay, susp, trustFloor }),
  });
}

function explainTrace({ rules, decay, susp, trustFloor }) {
  const lines = [];
  if (trustFloor != null) lines.push(`Trust floor applied at ${trustFloor}.`);
  if (decay.delta > 0)
    lines.push(
      `Trust decay -${decay.delta} from ${decay.anomalies.length} anomal${decay.anomalies.length === 1 ? "y" : "ies"}.`,
    );
  for (const r of rules.filter((x) => x.force))
    lines.push(`Forced ${r.force}: ${r.id} — ${r.reason}`);
  for (const r of rules.filter((x) => x.role === "cap")) lines.push(`Cap ${r.cap}: ${r.id}.`);
  if (susp) lines.push(`Suspicion band: ${susp.level} (modal=${susp.modal}).`);
  return lines;
}
