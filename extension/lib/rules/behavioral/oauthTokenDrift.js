// rule: oauth-token-drift — OAuth issuer and token-arrival origins differ.
export const ruleOauthTokenDrift = Object.freeze({
  id: "oauth-token-drift",
  category: "behavioral",
  severity: "high",
  description: "OAuth token arrives on an origin different from the issuer.",
  dependencies: ["authFlow"],
  evaluate(ctx) {
    const a = (ctx?.authFlow?.anomalies || []).find((x) => x.id === "oauth-token-drift");
    if (!a) return { matched: false, contribution: 0 };
    return { matched: true, contribution: -35, explain: a.explain };
  },
});
