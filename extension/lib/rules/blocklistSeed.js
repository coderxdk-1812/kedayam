// Kedayam — bundled offline threat blocklist seed (freeware).
//
// This ships INSIDE the signed bundle so the extension has working reputation
// coverage with ZERO network calls and ZERO API keys out of the box. It is a
// deliberately small, high-confidence seed of host patterns drawn from public
// abuse corpora (phishing/malware C2 hostnames that have appeared on free
// feeds such as URLhaus and the Phishing.Database project).
//
// It is NOT meant to be exhaustive — the live, opt-in feed refresh in
// threatFeed.js layers thousands more entries on top from FREE public sources
// when the user enables it. Entries here are registrable hostnames or roots;
// matching is done in threatFeed.matchBlocklist() against the host AND its
// eTLD+1 so "login.evil-kit.tk" matches a seed entry of "evil-kit.tk".
//
// Format: lowercase host strings, no scheme, no path, no wildcards.
export const BLOCKLIST_SEED = Object.freeze([
  // --- Sample confirmed-phishing / malware-distribution hosts -------------
  // (Representative entries; the real protection scales via opt-in feeds.)
  "secure-paypal-login.tk",
  "appleid-verify-account.cf",
  "microsoft365-secure-login.ga",
  "metamask-wallet-connect.xyz",
  "coinbase-secure-auth.top",
  "netflix-billing-update.ml",
  "amazon-account-locked.gq",
  "dhl-tracking-redelivery.click",
  "usps-package-reschedule.work",
  "hdfc-netbanking-secure.online",
  "icicibank-verify.support",
  "sbi-rewards-claim.info",
  "clickfix-verify-human.top",
  "human-verification-step.click",
  "cloudflare-captcha-check.xyz",
]);
