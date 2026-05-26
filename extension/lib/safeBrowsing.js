// Safe-browsing API connectors. Real keys are optional and pulled from settings.
// Without keys we degrade to local-only signals (still useful).

const TRUSTED_CDNS = [
  "googleapis.com", "gstatic.com", "googleusercontent.com", "google.com",
  "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com",
  "bootstrapcdn.com", "jquery.com", "fontawesome.com", "fonts.googleapis.com",
  "fonts.gstatic.com", "github.io", "githubusercontent.com", "vercel.app",
  "netlify.app", "amazonaws.com", "cloudfront.net", "akamaihd.net",
  "stripe.com", "stripe.network", "youtube.com", "ytimg.com",
];

export function isTrustedCdn(host) {
  if (!host) return false;
  return TRUSTED_CDNS.some((c) => host === c || host.endsWith("." + c));
}

const FETCH_TIMEOUT_MS = 4500;

function fetchWithTimeout(url, init = {}, timeoutMs = FETCH_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  return fetch(url, { ...init, signal: ctrl.signal })
    .finally(() => clearTimeout(t));
}

export async function checkGoogleSafeBrowsing(url, apiKey) {
  if (!apiKey) return { skipped: true, reason: "no-key" };
  try {
    const res = await fetchWithTimeout(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "kedayam", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }),
      }
    );
    if (!res.ok) return { skipped: true, reason: `http-${res.status}` };
    const data = await res.json();
    const matches = data.matches || [];
    return { skipped: false, malicious: matches.length > 0, threats: matches.map((m) => m.threatType) };
  } catch (e) {
    return { skipped: true, reason: e?.name === "AbortError" ? "timeout" : "network-error" };
  }
}

export async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return { skipped: true, reason: "no-key" };
  try {
    const id = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const res = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": apiKey, accept: "application/json" },
    });
    if (!res.ok) return { skipped: true, reason: `http-${res.status}` };
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    return {
      skipped: false,
      malicious: (stats.malicious || 0) > 0,
      stats,
    };
  } catch (e) {
    return { skipped: true, reason: e?.name === "AbortError" ? "timeout" : "network-error" };
  }
}