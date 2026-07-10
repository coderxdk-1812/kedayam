// Kedayam — pure helper that turns a list of ad/tracker domains into a
// declarativeNetRequest (DNR) static ruleset. Kept pure so it is unit-testable
// and the generated ruleset is deterministic.
//
// DNR `requestDomains` matches a domain AND its subdomains, so one entry per
// registrable ad/tracker host blocks the whole tree. We pack many domains into a
// few `block` rules (chunked) to keep the ruleset tiny and well under DNR limits.

// Chrome caps requestDomains/excludedRequestDomains combined at 1000 per rule.
const DEFAULT_CHUNK = 1000;

/**
 * @param {string[]} domains  bare lowercase hostnames (eTLD+1 or host)
 * @param {{ chunkSize?: number }} [opts]
 * @returns {Array<object>} DNR rules
 */
export function domainsToDnrRules(domains, opts = {}) {
  const chunkSize = Math.min(DEFAULT_CHUNK, Math.max(1, opts.chunkSize || DEFAULT_CHUNK));
  const clean = [...new Set((domains || []).map(normalizeDomain).filter(Boolean))].sort();
  const rules = [];
  for (let i = 0; i < clean.length; i += chunkSize) {
    rules.push({
      id: rules.length + 1,
      priority: 1,
      action: { type: "block" },
      condition: {
        requestDomains: clean.slice(i, i + chunkSize),
        // Only block third-party sub-resources — never the top-level page the
        // user navigated to (avoids "blank page" breakage if a domain is on both
        // the ad list and a site the user opens directly).
        resourceTypes: [
          "script",
          "image",
          "xmlhttprequest",
          "sub_frame",
          "media",
          "font",
          "ping",
          "websocket",
          "other",
        ],
      },
    });
  }
  return rules;
}

export function normalizeDomain(d) {
  if (typeof d !== "string") return "";
  let s = d.trim().toLowerCase();
  if (!s || s.startsWith("#") || s.startsWith("!")) return "";
  s = s.replace(/^\|\|/, "").replace(/[\^/].*$/, ""); // strip ABP artifacts
  s = s.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, "").replace(/^www\./, "");
  s = s.split(/\s+/)[0];
  if (!s.includes(".") || /[^a-z0-9.-]/.test(s) || s.length > 253) return "";
  return s;
}
