// Lookalike / typosquatting / homoglyph detection.
// Pure functions, fully local, no network calls.

const PROTECTED_BRANDS = [
  "google.com",
  "gmail.com",
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
  "apple.com",
  "icloud.com",
  "microsoft.com",
  "outlook.com",
  "live.com",
  "office.com",
  "amazon.com",
  "paypal.com",
  "netflix.com",
  "github.com",
  "linkedin.com",
  "twitter.com",
  "x.com",
  "dropbox.com",
  "adobe.com",
  "ionos.com",
  "1and1.com",
  "binance.com",
  "coinbase.com",
  "metamask.io",
  "chase.com",
  "wellsfargo.com",
  "bankofamerica.com",
  "hdfcbank.com",
  "icicibank.com",
  "sbi.co.in",
  "axisbank.com",
  "kotak.com",
  "rbi.org.in",
];

const HOMOGLYPHS = {
  a: ["а", "@", "4"],
  b: ["6", "ь"],
  c: ["с", "ϲ"],
  d: ["ԁ"],
  e: ["е", "3"],
  g: ["9", "ǵ"],
  h: ["һ"],
  i: ["і", "1", "l", "!"],
  k: ["к"],
  l: ["1", "I", "ӏ"],
  m: ["м"],
  n: ["п"],
  o: ["0", "о", "ο"],
  p: ["р", "ρ"],
  q: ["զ"],
  r: ["г"],
  s: ["ѕ", "5", "$"],
  t: ["т", "7"],
  u: ["υ", "ս"],
  v: ["ν", "ѵ"],
  w: ["ԝ"],
  x: ["х", "×"],
  y: ["у", "ү"],
  z: ["2"],
};

// Build a single glyph -> latin map. Each glyph maps to exactly one latin.
// Prefer non-ASCII glyph mappings over ASCII collisions (e.g. "l" should
// stay as "l", not be remapped to "i" just because it's listed under i:).
const GLYPH_MAP = (() => {
  const m = new Map();
  // First pass: non-ASCII only.
  for (const [latin, glyphs] of Object.entries(HOMOGLYPHS)) {
    for (const g of glyphs) {
      if (g.charCodeAt(0) > 127 && !m.has(g)) m.set(g, latin);
    }
  }
  // Second pass: ASCII (digits + a couple of safe punctuations). Skip any
  // glyph that is itself a-z, since "l" is already valid and remapping it
  // would corrupt strings like "paypal".
  for (const [latin, glyphs] of Object.entries(HOMOGLYPHS)) {
    for (const g of glyphs) {
      if (g.charCodeAt(0) > 127) continue;
      if (/[a-z]/i.test(g)) continue;
      if (!m.has(g)) m.set(g, latin);
    }
  }
  return m;
})();

export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length,
    n = b.length;
  if (!m) return n;
  if (!n) return m;
  const dp = new Array(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a[i - 1] === b[j - 1] ? prev : 1 + Math.min(prev, dp[j], dp[j - 1]);
      prev = tmp;
    }
  }
  return dp[n];
}

export function normalizeHomoglyphs(host) {
  let out = "";
  for (const ch of String(host || "")
    .normalize("NFKC")
    .toLowerCase()) {
    out += GLYPH_MAP.get(ch) ?? ch;
  }
  return out;
}

// Browser-compatible punycode decoder for IDN labels. Chrome's URL.hostname
// serializes many Unicode domains back to xn-- form, so extension code cannot
// rely on Node's punycode module being present in MV3 service workers.
export function decodePunycodeLabel(label) {
  const input = String(label || "").toLowerCase();
  if (!input.startsWith("xn--")) return label;
  const puny = input.slice(4);
  const out = [];
  const base = 36,
    tMin = 1,
    tMax = 26,
    skew = 38,
    damp = 700;
  let n = 128,
    i = 0,
    bias = 72;
  const adapt = (delta, numPoints, first) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (cp) => (cp >= 48 && cp <= 57 ? cp - 22 : cp >= 97 && cp <= 122 ? cp - 97 : base);
  const dash = puny.lastIndexOf("-");
  if (dash > -1) for (const ch of puny.slice(0, dash)) out.push(ch.codePointAt(0));
  let idx = dash > -1 ? dash + 1 : 0;
  while (idx < puny.length) {
    const oldI = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= puny.length) throw new Error("bad punycode");
      const d = digit(puny.charCodeAt(idx++));
      if (d >= base) throw new Error("bad punycode");
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    const len = out.length + 1;
    bias = adapt(i - oldI, len, oldI === 0);
    n += Math.floor(i / len);
    i %= len;
    out.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...out).normalize("NFKC");
}

export function toUnicodeHost(hostname) {
  return String(hostname || "")
    .replace(/^www\./i, "")
    .split(".")
    .map((label) => {
      try {
        return decodePunycodeLabel(label);
      } catch {
        return label;
      }
    })
    .join(".")
    .normalize("NFKC")
    .toLowerCase();
}

// ----------------------------------------------------------------------
// M-03 — Embedded Public Suffix List (PSL) subset.
//
// We need correct eTLD+1 ("root domain") extraction for country-code
// secondary domains used by major banking and identity providers in our
// supported regions. Embedding the full PSL would bloat the bundle and
// require periodic refreshes; instead we ship a deterministic, bounded
// subset covering AU, NZ, ZA, UK, JP, BR, IN — the highest-impact regions
// for the protected brands above.
//
// Lookup is O(1) per suffix length and never hits the network.
// ----------------------------------------------------------------------
const PSL_TWO_LEVEL = new Set([
  // United Kingdom
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "net.uk",
  "ltd.uk",
  "plc.uk",
  "me.uk",
  // India
  "co.in",
  "net.in",
  "org.in",
  "gen.in",
  "firm.in",
  "ind.in",
  "ac.in",
  "gov.in",
  // IDRBT/RBI-managed registry: every Indian bank gets <bank>.bank.in
  // (e.g. hdfc.bank.in, icici.bank.in), so bank.in is a public suffix.
  "bank.in",
  // Australia
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "asn.au",
  "id.au",
  // New Zealand
  "co.nz",
  "net.nz",
  "org.nz",
  "ac.nz",
  "govt.nz",
  "school.nz",
  "geek.nz",
  // South Africa
  "co.za",
  "net.za",
  "org.za",
  "web.za",
  "gov.za",
  "ac.za",
  // Japan
  "co.jp",
  "ne.jp",
  "or.jp",
  "ac.jp",
  "go.jp",
  "ad.jp",
  "ed.jp",
  "gr.jp",
  // Brazil
  "com.br",
  "net.br",
  "org.br",
  "gov.br",
  "edu.br",
  "ind.br",
  // Singapore / Hong Kong / others frequently seen with brand spoofing
  "com.sg",
  "edu.sg",
  "com.hk",
  "org.hk",
  "com.mx",
  "com.ar",
  "com.tr",
  // Pakistan
  "com.pk",
  "net.pk",
  "org.pk",
  "edu.pk",
  "gov.pk",
  "gob.pk",
  // Kenya
  "co.ke",
  "ne.ke",
  "or.ke",
  "ac.ke",
  "go.ke",
  "sc.ke",
  "me.ke",
  // Nigeria
  "com.ng",
  "net.ng",
  "org.ng",
  "edu.ng",
  "gov.ng",
  "sch.ng",
  // Indonesia
  "co.id",
  "net.id",
  "or.id",
  "ac.id",
  "go.id",
  "sch.id",
  "web.id",
  "my.id",
]);

export function rootDomain(host) {
  if (!host || typeof host !== "string") return host;
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join(".");
  if (PSL_TWO_LEVEL.has(last2) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

export function lookalikeAnalysis(hostname) {
  if (!hostname) return { match: null, confidence: 0, reasons: [] };
  const asciiHost = String(hostname)
    .toLowerCase()
    .replace(/^www\./, "");
  const host = toUnicodeHost(asciiHost);
  const root = rootDomain(host);
  const asciiRoot = rootDomain(asciiHost);
  const reasons = [];
  let best = null;
  const hasPunycode = /(^|\.)xn--/i.test(asciiHost);

  if (!hasPunycode && PROTECTED_BRANDS.includes(root)) {
    return { match: null, confidence: 0, reasons: ["Domain matches a known brand exactly."] };
  }

  const normalized = normalizeHomoglyphs(root);
  if (normalized !== root && PROTECTED_BRANDS.includes(normalized)) {
    reasons.push(`Visual look-alike of ${normalized} (homoglyph substitution).`);
    best = { brand: normalized, distance: 0, kind: "homoglyph" };
  }
  if (hasPunycode) {
    reasons.push(`Punycode/IDN hostname decodes to ${host}.`);
    if (!best) best = { brand: null, distance: 99, kind: "punycode" };
  }

  for (const brand of PROTECTED_BRANDS) {
    const d = Math.min(
      levenshtein(root, brand),
      levenshtein(normalized, brand),
      levenshtein(asciiRoot, brand),
    );
    if (d > 0 && d <= 2 && Math.abs(normalized.length - brand.length) <= 3) {
      if (!best || d < best.distance) {
        best = { brand, distance: d, kind: "typo" };
      }
    }
    // Brand name appears as its own token inside an unrelated host
    // (e.g. "paypal" in paypal.secure-login.tld). Require ≥4-char brand
    // names and word-boundary matching to avoid trivial substrings like
    // "x" matching inside "example.com".
    const brandName = brand.split(".")[0];
    if (brandName.length >= 4 && normalized !== brand) {
      const re = new RegExp(`(^|[.-])${brandName}([.-]|$)`, "i");
      if (re.test(host) || re.test(normalized) || re.test(asciiHost)) {
        reasons.push(`Brand name "${brandName}" appears in a non-${brand} domain.`);
        if (!best) best = { brand, distance: 99, kind: "brand-in-host" };
      }
    }
  }

  if (!best) return { match: null, confidence: 0, reasons };

  const confidence =
    best.kind === "homoglyph"
      ? 0.95
      : best.kind === "punycode"
        ? 0.75
        : best.kind === "typo"
          ? Math.max(0.6, 1 - best.distance * 0.2)
          : 0.55;

  if (best.kind === "typo") {
    reasons.push(`Edit distance ${best.distance} from ${best.brand}.`);
  }

  return { match: best, confidence, reasons };
}
