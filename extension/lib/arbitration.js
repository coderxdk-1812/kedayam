// Kedayam — deterministic arbitration engine.
//
// Trust philosophy: "unknown until trust is earned" (NOT "safe until danger
// is found"). The arbitration engine applies hard, ordered, rule-based
// precedence on top of the additive scoring done by the trust engine.
//
// Each rule is a pure predicate on the engine's inputs. Rules are ordered
// from most severe (force dangerous) to least. The first matching rule sets
// `forceStatus` and a hard `cap`. Subsequent rules can still tighten the
// cap if their bound is lower, so multiple corroborating signals never
// loosen a verdict.
//
// This module deliberately knows nothing about how the score was built —
// it only consumes the analytical outputs (lookalike, phishing, clone) plus
// the few flags (allowlist, hasAuthWorkflow, isReputableRoot) the trust
// engine derives. That separation makes arbitration auditable and testable
// in isolation.

/**
 * @typedef {Object} ArbitrationInput
 * @property {boolean} allowlistRoot         - root domain is on user allowlist
 * @property {boolean} isReputableRoot       - root in KNOWN_REPUTABLE_ROOTS
 * @property {boolean} isTrustedProvider     - root in TRUSTED_LOGIN_PROVIDERS
 * @property {boolean} hasAuthWorkflow       - any sign-in / credential intent detected
 * @property {{match:any, confidence:number}} lookalike
 * @property {boolean} idnSpoof              - punycode/xn-- in hostname
 * @property {{ confidence:number, externalFormPost?:boolean, brandImageMismatch?:boolean }} clone
 * @property {{ credentialHarvest:boolean, externalFormPost:boolean,
 *              brandImpersonation:any, confidence:number, authRisk:string }} phishing
 */

/**
 * @param {ArbitrationInput} ctx
 * @returns {{ cap:number|null, forceStatus:string|null,
 *             rules:Array<{id:string,reason:string,cap:number,force?:string}> }}
 */
// Centralized constants — every cap and threshold is auditable in one place.
export const ARB_CONST = Object.freeze({
  CAP_EXTERNAL_POST_CLONE: 15,
  CAP_EXTERNAL_POST: 20,
  CAP_CROSS_ORIGIN_CREDS: 20,
  CAP_OAUTH_SPOOF: 22,
  CAP_LOOKALIKE_CREDS: 25,
  CAP_BRAND_CREDS: 25,
  CAP_CLONE_AUTH: 25,
  CAP_LAYOUT_CLONE: 25,
  CAP_IDN_CREDS: 25,
  CAP_MFA_HARVEST_UNKNOWN: 25,
  CAP_HIDDEN_LOGIN: 35,
  CAP_LOOKALIKE_STRONG: 35,
  CAP_CLONE_MEDIUM: 35,
  CAP_IDN_AUTH: 30,
  CAP_BRAND_TEXT: 45,
  CAP_IDN: 45,
  CAP_EMAIL_FIRST: 55,
  CAP_CLONE_SOFT: 55,
  CAP_TRUSTED_BUT_SUSPICIOUS: 55,
  CAP_UNKNOWN_LOGIN: 60,
  CAP_UNKNOWN_AUTH: 70,
});

export function arbitrate(ctx) {
  const out = { cap: null, forceStatus: null, rules: [] };
  if (!ctx) return out;

  const C = ARB_CONST;
  const lookalikeConf = ctx.lookalike?.confidence || 0;
  const cloneConf = ctx.clone?.confidence || 0;
  const phishConf = ctx.phishing?.confidence || 0;
  const credentialHarvest = !!ctx.phishing?.credentialHarvest;
  const externalFormPost = !!(ctx.phishing?.externalFormPost || ctx.clone?.externalFormPost);
  const brandImpersonation = !!ctx.phishing?.brandImpersonation;
  const brandImageMismatch = !!ctx.clone?.brandImageMismatch;
  const isUnknown = !ctx.isReputableRoot && !ctx.isTrustedProvider;
  const sigs = ctx.phishing?.signals || [];
  const hasSig = (id) => sigs.some((s) => s.id === id);
  const crossOriginCreds = hasSig("iframe-credential-form") ||
    hasSig("iframe-login");
  const oauthSpoof = !!ctx.phishing?.oauthSpoof ||
    (hasSig("oauth-impersonation") && externalFormPost);
  const hiddenOverlay = !!ctx.hiddenLoginOverlay;
  const mfaOnly = !!ctx.mfaOnly ||
    !!(ctx.phishing?.forms || []).some((f) => f.hasOtp && !f.hasPassword);
  const emailFirst = !!ctx.emailFirstFlow ||
    !!(ctx.phishing?.forms || []).some((f) =>
      f.hasEmailLike && !f.hasPassword && (f.fieldsCount || 0) <= 4);
  const layoutCloneConf = ctx.authLayout?.confidence || 0;
  const layoutClone = !!ctx.authLayout?.isLayoutClone;

  // Allowlist short-circuit — narrowed (Issue C-02).
  // The user allowlist is a TRUST primitive: it raises the floor and
  // suppresses weak heuristics (visual similarity, IDN-only, soft clone).
  // It does NOT bypass active behavioral evidence of credential theft —
  // external POST, cross-origin credential iframes, OAuth spoofing,
  // or threat-intel hits. Allowlists must never silence exfiltration.
  const malicious = externalFormPost || crossOriginCreds || oauthSpoof ||
    !!ctx.gsbMalicious || !!ctx.vtMalicious;
  if (ctx.allowlistRoot && !malicious) return out;

  function apply(rule) {
    out.rules.push(rule);
    out.cap = out.cap == null ? rule.cap : Math.min(out.cap, rule.cap);
    if (rule.force) {
      const order = { safe: 0, suspicious: 1, dangerous: 2 };
      if (!out.forceStatus || order[rule.force] > order[out.forceStatus]) {
        out.forceStatus = rule.force;
      }
    }
  }

  // Behavioral corroboration — these are the *real* attack signals.
  // Clone / layout similarity alone NEVER produces a dangerous verdict
  // on a reputable or trusted root. It must be paired with one of these.
  const behavioralEvidence = externalFormPost || crossOriginCreds ||
    oauthSpoof || ctx.idnSpoof || mfaOnly || brandImpersonation ||
    !!ctx.gsbMalicious || !!ctx.vtMalicious;
  const trustedRoot = ctx.isReputableRoot || ctx.isTrustedProvider;

  // ---- Tier 1: hard "dangerous" overrides (high-confidence phishing) ----

  if (externalFormPost && (brandImpersonation || brandImageMismatch || cloneConf >= 0.6)) {
    apply({ id: "external-post-clone", force: "dangerous", cap: 15,
      reason: "Credentials would be POSTed off-domain on a clone/impersonation page." });
  }
  if (externalFormPost) {
    apply({ id: "external-post", force: "dangerous", cap: 20,
      reason: "Login form submits to an unrelated domain." });
  }
  if (lookalikeConf > 0.9 && credentialHarvest && isUnknown) {
    apply({ id: "lookalike-creds", force: "dangerous", cap: 25,
      reason: "Hostname mimics a known brand and is collecting credentials." });
  }
  if (brandImpersonation && credentialHarvest && isUnknown) {
    apply({ id: "brand-creds", force: "dangerous", cap: 25,
      reason: "Page impersonates a known brand and is collecting credentials." });
  }
  // High-confidence clone with credential workflow — ONLY when paired with
  // independent behavioral evidence. Visual similarity alone (favicon CDN,
  // logo reuse, asset hosts) is expected on legitimate brand pages and
  // must not escalate on its own.
  if (cloneConf >= 0.8 && (credentialHarvest || ctx.hasAuthWorkflow) &&
      isUnknown && behavioralEvidence) {
    apply({ id: "clone-auth", force: "dangerous", cap: 25,
      reason: "High-confidence visual clone of a known brand login combined with malicious behavior." });
  }
  if (ctx.idnSpoof && credentialHarvest) {
    apply({ id: "idn-creds", force: "dangerous", cap: C.CAP_IDN_CREDS,
      reason: "Punycode hostname is collecting credentials." });
  }
  if (crossOriginCreds && isUnknown) {
    apply({ id: "cross-origin-credentials", force: "dangerous",
      cap: C.CAP_CROSS_ORIGIN_CREDS,
      reason: "Password field inside a cross-origin iframe." });
  }
  if (oauthSpoof && isUnknown) {
    apply({ id: "oauth-spoof", force: "dangerous", cap: C.CAP_OAUTH_SPOOF,
      reason: "OAuth button posts credentials to an unrelated origin." });
  }
  if (mfaOnly && isUnknown) {
    apply({ id: "mfa-harvest", force: "dangerous",
      cap: C.CAP_MFA_HARVEST_UNKNOWN,
      reason: "Unknown domain is requesting only an MFA / OTP code." });
  }
  if (layoutClone && isUnknown && behavioralEvidence) {
    apply({ id: "auth-layout-clone", force: "dangerous",
      cap: C.CAP_LAYOUT_CLONE,
      reason: "Sign-in layout matches a known provider on an unrelated domain with malicious behavior." });
  }

  // ---- Tier 2: "suspicious" caps (need corroboration to escalate) ----

  if (lookalikeConf > 0.85 && isUnknown) {
    apply({ id: "lookalike-strong", force: "suspicious", cap: 35,
      reason: "Hostname strongly resembles a protected brand." });
  }
  if (ctx.idnSpoof && ctx.hasAuthWorkflow) {
    apply({ id: "idn-auth", force: "suspicious", cap: 30,
      reason: "Punycode hostname combined with authentication workflow." });
  }
  if (ctx.idnSpoof) {
    apply({ id: "idn", force: "suspicious", cap: 45,
      reason: "Punycode / Unicode hostname." });
  }
  // Layout-only match on an unknown root, no behavioral evidence: surface
  // as suspicious but do not escalate to dangerous.
  if (layoutClone && isUnknown && !behavioralEvidence) {
    apply({ id: "auth-layout-soft-unknown", force: "suspicious",
      cap: C.CAP_LAYOUT_CLONE + 10,
      reason: "Sign-in layout matches a known provider on an unrelated domain." });
  }
  // Clone signals only escalate when on unknown roots OR with behavioral
  // evidence. On trusted/reputable roots, visual similarity is informational.
  if (cloneConf >= 0.6 && isUnknown) {
    apply({ id: "clone-medium", force: "suspicious", cap: 35,
      reason: "Page resembles a cloned brand site." });
  } else if (cloneConf >= 0.4 && isUnknown) {
    apply({ id: "clone-soft", cap: 55,
      reason: "Some structural signs of brand cloning." });
  }
  if (brandImpersonation && !ctx.isReputableRoot) {
    apply({ id: "brand-text", force: "suspicious", cap: 45,
      reason: "Page mentions a major brand it does not belong to." });
  }
  if (credentialHarvest && isUnknown) {
    apply({ id: "unknown-login", cap: 60,
      reason: "Credential form on an unverified domain." });
    if (phishConf >= 0.5) out.forceStatus = out.forceStatus || "suspicious";
  }
  if (ctx.hasAuthWorkflow && !credentialHarvest && isUnknown) {
    apply({ id: "unknown-auth", cap: C.CAP_UNKNOWN_AUTH,
      reason: "Authentication workflow on an unverified domain." });
  }
  if (hiddenOverlay && isUnknown) {
    apply({ id: "hidden-overlay", force: "suspicious",
      cap: C.CAP_HIDDEN_LOGIN,
      reason: "Login UI was hidden initially and revealed dynamically." });
  }
  if (emailFirst && isUnknown && !credentialHarvest) {
    apply({ id: "email-first", force: "suspicious", cap: C.CAP_EMAIL_FIRST,
      reason: "Email-first capture flow on an unverified domain." });
  }
  if (!layoutClone && layoutCloneConf >= 0.5 && isUnknown) {
    apply({ id: "auth-layout-soft", cap: C.CAP_CLONE_SOFT,
      reason: `Sign-in layout partially matches ${ctx.authLayout?.matchedTemplate || "a known provider"}.` });
  }

  // ---- Tier 3: trusted-provider corroboration ----
  // We only escalate a trusted root to "suspicious" when real behavioral
  // evidence agrees. Visual similarity alone is expected on legitimate
  // brand pages and must never trigger a warning.
  if (ctx.isTrustedProvider && behavioralEvidence &&
      (lookalikeConf > 0.85 || cloneConf >= 0.6)) {
    apply({ id: "trusted-but-suspicious", force: "suspicious", cap: 55,
      reason: "Trusted provider root, but page shows behavioral attack signals." });
  }

  // ---- Tier 4: shadow arbitration on trusted roots ----
  // Trusted / reputable roots benefit from a hard trust floor when no
  // behavioral evidence is present. Clone, layout, and lookalike heuristics
  // still compute (for local diagnostics), but cannot pull the score below
  // the floor without corroboration. This eliminates catastrophic false
  // positives on brands like github.com whose assets legitimately live on
  // sibling domains (e.g. githubassets.com).
  if (trustedRoot && !behavioralEvidence) {
    const floor = ctx.isReputableRoot ? 85 : 80;
    out.trustFloor = floor;
    out.shadowSuppressed = out.rules
      .filter((r) => r.force === "dangerous" || r.force === "suspicious")
      .map((r) => r.id);
    // Strip any force* / low caps imposed by visual heuristics.
    out.forceStatus = null;
    out.cap = null;
    out.rules.push({
      id: "trusted-root-floor",
      cap: 100,
      reason: `Trusted root ${ctx.isReputableRoot ? "(reputable)" : "(identity provider)"} — visual similarity alone is not actionable; no credential exfiltration detected.`,
    });
  }

  return out;
}
