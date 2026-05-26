// Enterprise auth realism suite — these are legitimate-looking corporate IdPs.
// The assertion is *low false positives* on each: no dangerous modal should
// fire purely from layout/keywords. Behavioral evidence (off-domain POST,
// iframe origin swap) is the only acceptable escalator.
import { describe, it, expect } from "vitest";
import { evaluateUrl } from "../../extension/lib/trustEngine.js";

const settings = { detection: { sensitivity: "balanced" }, apiKeys: {}, allowlist: [] };

function basicAuthPageContext(origin, formAction) {
  return {
    pageOrigin: origin, title: "Sign in",
    visibleText: "sign in to your account",
    hasPasswordField: true,
    forms: [{ action: formAction, method: "post",
      hasPassword: true, hasEmailLike: true, hasOtp: false,
      hiddenCount: 0, fieldsCount: 2, insideIframe: false }],
  };
}

describe("enterprise auth realism (M7)", () => {
  it("Okta whitelabel tenant is NOT dangerous", async () => {
    const r = await evaluateUrl("https://acme.okta.com/login", {
      settings,
      pageContext: basicAuthPageContext("https://acme.okta.com",
        "https://acme.okta.com/api/v1/authn"),
    });
    expect(r.status).not.toBe("dangerous");
    expect(r.suspicion.modal).not.toBe("hard");
  });

  it("Azure AD enterprise tenant is NOT dangerous", async () => {
    const r = await evaluateUrl("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", {
      settings,
      pageContext: basicAuthPageContext("https://login.microsoftonline.com",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
    });
    expect(r.status).not.toBe("dangerous");
  });

  it("ADFS internal portal stays at contextual or below", async () => {
    const r = await evaluateUrl("https://adfs.acme.com/adfs/ls", {
      settings,
      pageContext: basicAuthPageContext("https://adfs.acme.com",
        "https://adfs.acme.com/adfs/ls"),
    });
    expect(r.suspicion.modal).not.toBe("hard");
  });

  it("PingFederate sign-on stays at contextual or below", async () => {
    const r = await evaluateUrl("https://sso.acme.com/idp/SSO.saml2", {
      settings,
      pageContext: basicAuthPageContext("https://sso.acme.com",
        "https://sso.acme.com/idp/SSO.saml2"),
    });
    expect(r.suspicion.modal).not.toBe("hard");
  });

  it("but a corporate-looking page POSTing off-domain IS dangerous", async () => {
    const r = await evaluateUrl("https://acme-corp-login.tld/", {
      settings,
      pageContext: basicAuthPageContext("https://acme-corp-login.tld",
        "https://harvester.cc/grab"),
    });
    expect(r.status).toBe("dangerous");
    expect(r.suspicion.modal).toBe("hard");
  });

  it("trace exposes lineage on every verdict", async () => {
    const r = await evaluateUrl("https://acme.okta.com/login", {
      settings, pageContext: basicAuthPageContext("https://acme.okta.com",
        "https://acme.okta.com/api/v1/authn"),
    });
    expect(r.trace).toBeDefined();
    expect(r.trace.version).toBe(1);
    expect(Array.isArray(r.trace.rules)).toBe(true);
    expect(r.trace.suspicion).toBeDefined();
  });
});
