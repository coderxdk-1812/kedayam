// Kedayam — curated static safelist of well-known sign-in providers,
// banking portals, password managers and federated SSO surfaces.
//
// Hard rules:
//   • Static. No remote update. No fetched rule packs.
//   • Versioned via SAFELIST_VERSION — bump on every change for auditing.
//   • Root domains only (e.g. "google.com", not "accounts.google.com").
//   • Reviewers can audit the diff in version control.
//
// This list does NOT grant a site "always safe" — it only suppresses
// false-positive credential-harvest signals and skips brand-impersonation
// flags when the page is ON its own legitimate root.

export const SAFELIST_VERSION = 1;

const _IDP = [
  "google.com", "accounts.google.com",
  "microsoft.com", "microsoftonline.com", "live.com", "office.com",
  "apple.com", "icloud.com",
  "okta.com", "auth0.com", "onelogin.com", "duosecurity.com", "pingidentity.com",
  "github.com", "gitlab.com", "bitbucket.org",
  "facebook.com", "linkedin.com",
];

const _BANKING = [
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
  "capitalone.com", "usbank.com", "americanexpress.com",
  "hsbc.com", "barclays.co.uk", "lloydsbank.com", "natwest.com",
  "santander.com", "bnpparibas.com", "deutschebank.com",
  "scotiabank.com", "td.com", "rbc.com",
  "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
];

const _PAYMENTS = [
  "paypal.com", "stripe.com", "wise.com", "revolut.com",
  "venmo.com", "cashapp.com", "squareup.com",
];

const _PWMGR = [
  "1password.com", "bitwarden.com", "lastpass.com",
  "dashlane.com", "keepersecurity.com", "nordpass.com",
];

const _SAAS_TRUSTED = [
  "salesforce.com", "workday.com", "atlassian.com",
  "slack.com", "zoom.us", "dropbox.com", "box.com",
];

export const SAFELIST = Object.freeze({
  version: SAFELIST_VERSION,
  identityProviders: Object.freeze([..._IDP]),
  banking:           Object.freeze([..._BANKING]),
  payments:          Object.freeze([..._PAYMENTS]),
  passwordManagers:  Object.freeze([..._PWMGR]),
  saas:              Object.freeze([..._SAAS_TRUSTED]),
});

const _ALL = new Set([
  ..._IDP, ..._BANKING, ..._PAYMENTS, ..._PWMGR, ..._SAAS_TRUSTED,
]);

/** True if `root` is a curated provider root. Case-insensitive. */
export function isSafelistedRoot(root) {
  if (!root || typeof root !== "string") return false;
  return _ALL.has(root.toLowerCase());
}

/** Category lookup for explanations. */
export function safelistCategory(root) {
  if (!root) return null;
  const r = root.toLowerCase();
  if (_IDP.includes(r)) return "identity-provider";
  if (_BANKING.includes(r)) return "banking";
  if (_PAYMENTS.includes(r)) return "payments";
  if (_PWMGR.includes(r)) return "password-manager";
  if (_SAAS_TRUSTED.includes(r)) return "saas";
  return null;
}
