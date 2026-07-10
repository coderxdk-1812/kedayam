// rule: external-form-post — credential form POSTs to a different root.
import { rootDomain } from "../../lookalike.js";

export const ruleExternalFormPost = Object.freeze({
  id: "external-form-post",
  category: "phishing",
  severity: "critical",
  description: "Credential form action targets a different registered domain than the page itself.",
  evaluate(ctx) {
    const forms = ctx.forms || [];
    const pageRoot =
      ctx.pageRoot || (ctx.pageOrigin ? rootDomain(new URL(ctx.pageOrigin).host) : null);
    if (!pageRoot) return { matched: false, contribution: 0 };
    for (const f of forms) {
      if (!f.action || !(f.hasPassword || f.hasOtp)) continue;
      try {
        const u = new URL(f.action, ctx.pageOrigin || "https://_/");
        const ar = rootDomain(u.host.replace(/^www\./, ""));
        if (ar && ar !== pageRoot) {
          return {
            matched: true,
            contribution: -60,
            explain: `Credential form on ${pageRoot} posts to ${ar}.`,
          };
        }
      } catch {
        /* invalid action — handled elsewhere */
      }
    }
    return { matched: false, contribution: 0 };
  },
});
