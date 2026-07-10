// rule: brand-keyword-mismatch — page text/title mentions a brand but is
// hosted off that brand's known roots.
import { rootDomain } from "../../lookalike.js";

const BRANDS = Object.freeze({
  "microsoft.com": [/microsoft/i, /office\s*365/i, /outlook/i, /onedrive/i],
  "google.com": [/gmail/i, /google\s*account/i],
  "apple.com": [/apple\s*id/i, /icloud/i],
  "paypal.com": [/paypal/i],
  "amazon.com": [/amazon/i, /aws/i],
  "github.com": [/github/i],
});

export const ruleBrandKeywordMismatch = Object.freeze({
  id: "brand-keyword-mismatch",
  category: "phishing",
  severity: "high",
  description: "Page text impersonates a known brand on a domain that brand does not own.",
  evaluate(ctx) {
    const text = ((ctx.title || "") + " " + (ctx.visibleText || "")).slice(0, 4000);
    const pageRoot =
      ctx.pageRoot || (ctx.pageOrigin ? rootDomain(new URL(ctx.pageOrigin).host) : null);
    if (!pageRoot || !text) return { matched: false, contribution: 0 };
    for (const [root, patterns] of Object.entries(BRANDS)) {
      if (pageRoot === root) continue;
      if (patterns.some((re) => re.test(text))) {
        return {
          matched: true,
          contribution: -35,
          explain: `Page mentions ${root} but is hosted on ${pageRoot}.`,
        };
      }
    }
    return { matched: false, contribution: 0 };
  },
});
