// Kedayam — formal rule registry (M4).
//
// Each rule is a pure function with a stable id, declared severity, category,
// and declared dependencies. Rules NEVER mutate the context; they return a
// `{ matched, contribution, explain }` triple. Pure rules can be replayed
// in tests deterministically without booting a browser.
//
// Categories: phishing | auth | trust | behavioral | antiEvasion
// Add new rules under the matching subdirectory and re-export here.

/** @typedef {Object} RuleContext
 *  @property {string} [pageRoot]
 *  @property {string} [pageOrigin]
 *  @property {boolean} [hasPassword]
 *  @property {Array}   [forms]
 *  @property {Object}  [phishing]
 *  @property {Object}  [clone]
 *  @property {Object}  [authLayout]
 *  @property {Object}  [authFlow]
 *  @property {boolean} [isSafelisted]
 *  @property {boolean} [hasAuthWorkflow]
 *  @property {boolean} [cspChecked]
 *  @property {boolean} [cspPresent]
 */

/** @typedef {Object} RuleResult
 *  @property {boolean} matched
 *  @property {number}  contribution
 *  @property {string}  [explain]
 */

/** @typedef {Object} Rule
 *  @property {string}   id
 *  @property {string}   category
 *  @property {string}   severity
 *  @property {string[]} [dependencies]
 *  @property {string}   description
 *  @property {(ctx: RuleContext) => RuleResult} evaluate
 */

import { ruleExternalFormPost }       from "./phishing/externalFormPost.js";
import { ruleBrandKeywordMismatch }   from "./phishing/brandMismatch.js";
import { ruleMfaOnlyOnUnknownDomain } from "./auth/mfaOnlyUnknown.js";
import { ruleSafelistedRoot }         from "./trust/safelisted.js";
import { ruleCredentialRelay }        from "./behavioral/credentialRelay.js";
import { ruleOauthTokenDrift }        from "./behavioral/oauthTokenDrift.js";
import { ruleIframeOriginSwap }       from "./behavioral/iframeOriginSwap.js";
import { ruleCspDowngrade }           from "./antiEvasion/cspDowngrade.js";

export const RULES = Object.freeze([
  ruleExternalFormPost,
  ruleBrandKeywordMismatch,
  ruleMfaOnlyOnUnknownDomain,
  ruleSafelistedRoot,
  ruleCredentialRelay,
  ruleOauthTokenDrift,
  ruleIframeOriginSwap,
  ruleCspDowngrade,
]);

export const RULES_BY_ID = Object.freeze(
  Object.fromEntries(RULES.map((r) => [r.id, r])),
);

export const RULES_BY_CATEGORY = Object.freeze(
  RULES.reduce((acc, r) => {
    (acc[r.category] ||= []).push(r);
    return acc;
  }, {}),
);

export function evaluateAll(ctx) {
  const out = [];
  for (const r of RULES) {
    let result;
    try { result = r.evaluate(ctx) || { matched: false, contribution: 0 }; }
    catch { result = { matched: false, contribution: 0, explain: "[rule error]" }; }
    out.push({ id: r.id, severity: r.severity, category: r.category, ...result });
  }
  return out;
}

export const REGISTRY_VERSION = 2;
