// rule: mfa-only-unknown — OTP-only form on a non-safelisted domain.
export const ruleMfaOnlyOnUnknownDomain = Object.freeze({
  id: "mfa-only-unknown",
  category: "auth",
  severity: "high",
  description: "Page collects only a one-time code on an unverified domain.",
  evaluate(ctx) {
    if (ctx.isSafelisted) return { matched: false, contribution: 0 };
    const forms = ctx.forms || [];
    if (!forms.length) return { matched: false, contribution: 0 };
    const allMfaOnly = forms.every((f) => f.hasOtp && !f.hasPassword);
    if (!allMfaOnly) return { matched: false, contribution: 0 };
    return {
      matched: true,
      contribution: -30,
      explain: "Only an MFA code is being collected on an unverified domain.",
    };
  },
});
