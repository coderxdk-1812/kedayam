// rule: csp-downgrade — Content-Security-Policy was weakened (or removed)
// on a page that handles credentials. Anti-evasion: many phishing kits ship
// without CSP to allow inline injected exfiltration scripts.
export const ruleCspDowngrade = Object.freeze({
  id: "csp-downgrade",
  category: "antiEvasion",
  severity: "low",
  description: "Page collecting credentials has no Content-Security-Policy.",
  evaluate(ctx) {
    if (!ctx?.hasAuthWorkflow) return { matched: false, contribution: 0 };
    if (ctx?.cspPresent) return { matched: false, contribution: 0 };
    if (!ctx?.cspChecked) return { matched: false, contribution: 0 };
    return {
      matched: true,
      contribution: -8,
      explain: "Credential page is served without a Content-Security-Policy header.",
    };
  },
});
