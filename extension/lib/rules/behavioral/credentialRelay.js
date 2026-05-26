// rule: credential-relay — auth-flow graph reports a credential POST to an
// origin never visited during the in-tab auth flow. Behavior-only; brand-
// agnostic.
export const ruleCredentialRelay = Object.freeze({
  id: "credential-relay",
  category: "behavioral",
  severity: "high",
  description: "Credential step targets an origin not seen earlier in the flow.",
  dependencies: ["authFlow"],
  evaluate(ctx) {
    const anoms = ctx?.authFlow?.anomalies || [];
    const hit = anoms.find((a) => a.id === "credential-relay");
    if (!hit) return { matched: false, contribution: 0 };
    return { matched: true, contribution: -50, explain: hit.explain };
  },
});
