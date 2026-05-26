// rule: iframe-origin-swap — credential entry happens in a child iframe whose
// origin differs from the parent entry origin. Brand-agnostic.
export const ruleIframeOriginSwap = Object.freeze({
  id: "iframe-origin-swap",
  category: "behavioral",
  severity: "medium",
  description: "Credentials collected inside a foreign-origin iframe.",
  dependencies: ["authFlow"],
  evaluate(ctx) {
    const a = (ctx?.authFlow?.anomalies || []).find((x) => x.id === "iframe-origin-swap");
    if (!a) return { matched: false, contribution: 0 };
    return { matched: true, contribution: -25, explain: a.explain };
  },
});
