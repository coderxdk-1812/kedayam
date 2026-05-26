// rule: safelisted-root — boosts trust when the page is on a curated
// identity / banking / SaaS root. Never grants a blanket pass; the
// arbitration layer still considers external POST signals.
import { isSafelistedRoot, safelistCategory } from "../../safelist.js";

export const ruleSafelistedRoot = Object.freeze({
  id: "safelisted-root",
  category: "trust",
  severity: "info",
  description: "Page is hosted on a curated, well-known root domain.",
  evaluate(ctx) {
    if (!ctx.pageRoot) return { matched: false, contribution: 0 };
    if (!isSafelistedRoot(ctx.pageRoot)) return { matched: false, contribution: 0 };
    return {
      matched: true, contribution: +10,
      explain: `Recognised ${safelistCategory(ctx.pageRoot)} provider: ${ctx.pageRoot}.`,
    };
  },
});
