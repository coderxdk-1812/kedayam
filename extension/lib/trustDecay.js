// Kedayam — Trust Anomaly Decay (M3).
//
// Trusted roots (reputable list + identity providers + user allowlist) get
// a baseline trust floor that *decays* sharply when contradictory
// behaviors appear in the same evaluation. This prevents "trusted-domain
// blindness": a compromised github.com page that POSTs credentials off-domain
// should NOT keep its trust floor.
//
// The function is pure — given the same inputs it returns the same delta
// and reason set. The trustEngine applies the delta after arbitration but
// before the final score clamp.

const ANOMALY_WEIGHTS = Object.freeze({
  "external-credential-post":  60,
  "cross-origin-cred-iframe":  35,
  "oauth-relay-mismatch":      30,
  "hidden-login-overlay":      15,
  "csp-weakening":             10,
  "abnormal-redirect-chain":   12,
  "auth-flow-mutation":        18,
});

/**
 * @param {Object} ctx
 * @param {boolean} [ctx.trustedRoot]
 * @param {boolean} [ctx.behavioralEvidence]
 * @param {Object}  [ctx.arbitration]   — full arbitration result
 * @param {Object}  [ctx.phishing]
 * @param {Object}  [ctx.authFlow]      — { anomalies:[{id,...}] }
 * @returns {{ delta:number, anomalies:Array<{id:string,points:number,explain:string}>,
 *             floorOverride:number|null }}
 */
export function trustDecay(ctx = {}) {
  const out = { delta: 0, anomalies: [], floorOverride: null };
  if (!ctx.trustedRoot) return out;

  const phish = ctx.phishing || {};
  const sigs = phish.signals || [];
  const has  = (id) => sigs.some((s) => s.id === id);
  const flow = ctx.authFlow || {};
  const flowAnoms = Array.isArray(flow.anomalies) ? flow.anomalies : [];
  const flowHas = (id) => flowAnoms.some((a) => a.id === id);

  function fire(id, explain) {
    const points = ANOMALY_WEIGHTS[id] || 5;
    out.delta += points;
    out.anomalies.push({ id, points, explain });
  }

  if (phish.externalFormPost) {
    fire("external-credential-post",
      "Trusted root is posting credentials off-domain.");
  }
  if (has("iframe-credential-form") || has("iframe-login") ||
      flowHas("iframe-origin-swap")) {
    fire("cross-origin-cred-iframe",
      "Credential field lives inside a foreign-origin iframe.");
  }
  if (flowHas("oauth-token-drift") || phish.oauthSpoof) {
    fire("oauth-relay-mismatch",
      "OAuth continuation lands on an unexpected origin.");
  }
  if (ctx.hiddenLoginOverlay) {
    fire("hidden-login-overlay",
      "A login overlay was revealed dynamically on a trusted root.");
  }
  if (ctx.cspWeakened) {
    fire("csp-weakening",
      "Content-Security-Policy was relaxed unexpectedly.");
  }
  if (flowHas("redirect-storm")) {
    fire("abnormal-redirect-chain",
      "Authentication crossed an unusual number of origins.");
  }
  if (flowHas("mfa-origin-split")) {
    fire("auth-flow-mutation",
      "Password and MFA collected on different origins.");
  }

  // When decay is substantial on a trusted root, lower the effective floor.
  if (out.delta >= 30) {
    out.floorOverride = Math.max(20, 85 - out.delta);
  } else if (out.delta > 0) {
    out.floorOverride = Math.max(55, 85 - out.delta);
  }
  return out;
}

export const TRUST_DECAY_WEIGHTS = ANOMALY_WEIGHTS;
