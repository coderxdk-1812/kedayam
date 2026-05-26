// Kedayam Trust Engine v2 — weighted, explainable, confidence-aware.
//
// Score model:
//   Start at 100. Each fired signal subtracts (weight * confidence) points.
//   Confidence is in [0, 1]. Weight is a soft cap on impact (in points).
//   Each signal returns a structured record carrying:
//     id, title, detail, severity, category, weight, confidence, contribution.
//   "contribution" is the actual point delta applied — surfaced verbatim in UI
//   so users see *why* a score moved.
//
// Categories (used for grouping in the popup):
//   "transport"  — TLS / HTTPS quality
//   "identity"   — domain age, lookalike, brand abuse
//   "structure"  — URL shape (IP host, embedded creds, dashes, deep subdomain)
//   "behavior"   — redirect chain, navigation oddities
//   "reputation" — Google Safe Browsing, VirusTotal
//   "trust"      — allowlist, learned-safe, session override

import { lookalikeAnalysis, rootDomain } from "./lookalike.js";
import { checkGoogleSafeBrowsing, checkVirusTotal } from "./safeBrowsing.js";
import { analyzeClone } from "./cloneDetection.js";
import { analyzePhishing } from "./phishingHeuristics.js";
import { arbitrate } from "./arbitration.js";
import { trustDecay } from "./trustDecay.js";
import { deriveSuspicion } from "./suspicionLevels.js";
import { buildArbitrationTrace } from "./arbitrationTrace.js";
import {
  analyzeSecurityContext,
  SECURITY_CONTEXT_THRESHOLD,
  dampenConfidence,
} from "./securityContext.js";

const NEW_DOMAIN_DAYS = 60;
const KNOWN_REPUTABLE_ROOTS = new Set([
  "example.com", "wikipedia.org", "github.com", "google.com", "microsoft.com",
  "apple.com", "paypal.com", "amazon.com", "linkedin.com", "youtube.com",
  "stripe.com", "cloudflare.com", "okta.com", "notion.so", "slack.com",
  "figma.com", "atlassian.com", "dropbox.com", "gitlab.com",
  "ionos.com", "1and1.com",
]);

// Trusted login providers — being on one of these roots reduces suspicion
// for a credential form, but does NOT by itself imply the page is safe.
// Corroborating signals (no lookalike, no clone, no off-domain POST) are
// still required by the arbitration engine.
const TRUSTED_LOGIN_PROVIDERS = new Set([
  "google.com", "microsoft.com", "microsoftonline.com", "live.com",
  "office.com", "office365.com", "outlook.com", "sharepoint.com",
  "apple.com", "icloud.com", "github.com", "gitlab.com", "atlassian.com",
  "slack.com", "dropbox.com", "notion.so", "figma.com", "okta.com",
  "auth0.com", "linkedin.com", "facebook.com", "x.com", "twitter.com",
  "amazon.com", "paypal.com", "stripe.com", "shopify.com", "netflix.com",
  "spotify.com", "adobe.com", "ionos.com", "1and1.com",
]);

// Sensitivity multiplier — applied to every penalty.
const SENS = { strict: 1.25, balanced: 1.0, lenient: 0.75 };

export async function evaluateUrl(url, ctx = {}) {
  const {
    settings,
    redirectChain = [],
    domainAgeDays = null,
    safeDomainStats = {}, // { [root]: { trustCount, lastTrustAt } }
    pageContext = null,    // { pageOrigin, scripts, styles, images, favicon }
  } = ctx;

  let parsed;
  try { parsed = new URL(url); } catch { return errorResult(url, "Invalid URL"); }
  const host = parsed.hostname;
  const root = rootDomain(host.replace(/^www\./, ""));
  const sens = SENS[settings?.detection?.sensitivity] ?? 1.0;

  /** @type {Array<Signal>} */
  const fired = [];
  const passed = [];
  const trustAdds = [];

  function fire(sig) {
    const conf = clamp01(sig.confidence ?? 1);
    const weight = Math.max(0, sig.weight ?? 0);
    const contribution = -Math.round(weight * conf * sens);
    fired.push({ ...sig, confidence: conf, weight, contribution });
  }
  function pass(sig) { passed.push({ ...sig, contribution: 0 }); }
  function addTrust(sig) {
    const points = Math.max(0, sig.points || 0);
    trustAdds.push({ ...sig, contribution: points, category: "trust",
      severity: "info" });
  }

  function capScore(maxScore, sig) {
    if (scoreCaps.some((c) => c.id === sig.id)) return;
    scoreCaps.push({ ...sig, maxScore, cap: true, contribution: 0 });
  }

  const scoreCaps = [];

  // --- transport ---
  if (parsed.protocol !== "https:") {
    fire({
      id: "no-https", category: "transport", severity: "high",
      title: "Connection is not encrypted",
      detail: "Served over plain HTTP. Any data you submit can be read in transit.",
      weight: 25, confidence: 1,
    });
  } else {
    pass({ id: "https", category: "transport", severity: "info",
      title: "Encrypted connection (HTTPS)" });
  }

  // --- identity: domain age ---
  if (typeof domainAgeDays === "number" && domainAgeDays >= 0 && domainAgeDays < NEW_DOMAIN_DAYS) {
    const conf = 1 - domainAgeDays / NEW_DOMAIN_DAYS;
    fire({
      id: "new-domain", category: "identity", severity: "medium",
      title: `Newly registered domain (${domainAgeDays} day${domainAgeDays === 1 ? "" : "s"})`,
      detail: "Phishing campaigns disproportionately use very fresh domains.",
      weight: 22, confidence: conf,
    });
  }

  // --- identity: lookalike / homoglyph ---
  const lookalike = lookalikeAnalysis(host);
  if (lookalike.match) {
    const sev = lookalike.confidence > 0.8 ? "critical" : "high";
    fire({
      id: "lookalike", category: "identity", severity: sev,
      title: `Visually resembles ${lookalike.match.brand}`,
      detail: lookalike.reasons.join(" "),
      weight: 45, confidence: lookalike.confidence,
    });
    if (lookalike.match.kind === "punycode" || /(^|\.)xn--/i.test(host)) {
      capScore(45, {
        id: "idn-risk-cap", category: "identity", severity: "high",
        title: "Trust capped for Punycode / Unicode hostname",
        detail: "Internationalized domains can be legitimate, but they are high-risk when combined with authentication or brand-like cues.",
      });
    }
  }

  // --- structure ---
  if (parsed.username || parsed.password) {
    fire({
      id: "userinfo", category: "structure", severity: "high",
      title: "URL contains embedded credentials",
      detail: "Legitimate sites do not put login info inside the URL.",
      weight: 20, confidence: 1,
    });
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    fire({
      id: "ip-host", category: "structure", severity: "medium",
      title: "Site is hosted at a raw IP address",
      detail: "Real services use named domains with valid certificates.",
      weight: 15, confidence: 1,
    });
  }
  const dashes = (host.match(/-/g) || []).length;
  if (dashes >= 4) {
    fire({
      id: "many-dashes", category: "structure", severity: "low",
      title: "Unusual number of hyphens in hostname",
      detail: `Found ${dashes} hyphens — common in throwaway phishing domains.`,
      weight: 6, confidence: Math.min(1, (dashes - 3) / 4),
    });
  }
  const depth = host.split(".").length;
  if (depth > 4) {
    fire({
      id: "deep-subdomain", category: "structure", severity: "low",
      title: "Deeply nested subdomain",
      detail: `${depth}-level hostname can disguise the real domain.`,
      weight: 6, confidence: Math.min(1, (depth - 4) / 3),
    });
  }
  if (host.length > 40) {
    fire({
      id: "long-host", category: "structure", severity: "low",
      title: "Unusually long hostname",
      weight: 4, confidence: Math.min(1, (host.length - 40) / 30),
    });
  }
  // Only flag auth keywords in the *hostname* of unknown roots — legitimate
  // providers like accounts.google.com naturally contain these words.
  const _earlyReputable = KNOWN_REPUTABLE_ROOTS.has(root) ||
    TRUSTED_LOGIN_PROVIDERS.has(root);
  if (/(login|verify|secure|account|update|wallet|signin)/i.test(host) &&
      !lookalike.match && !_earlyReputable) {
    fire({
      id: "auth-keyword", category: "structure", severity: "medium",
      title: "Auth-related keyword in hostname",
      detail: "Words like 'login' or 'verify' in the hostname (not the path) are a phishing tell.",
      weight: 10, confidence: 0.7,
    });
  }

  // --- behavior: redirects ---
  if (redirectChain.length > 3) {
    const hops = redirectChain.length;
    fire({
      id: "long-redirects", category: "behavior", severity: "medium",
      title: `Long redirect chain (${hops} hops)`,
      detail: redirectChain.slice(-5).join(" → "),
      weight: 12, confidence: Math.min(1, (hops - 3) / 5),
    });
  }
  // Cross-eTLD jump in the chain (e.g. ad.com → bank.com → bank-secure.tld)
  const chainHosts = redirectChain
    .map((u) => { try { return new URL(u).hostname; } catch { return ""; } })
    .filter(Boolean);
  const chainRoots = new Set(chainHosts.map((h) => rootDomain(h.replace(/^www\./, ""))));
  if (chainRoots.size >= 3) {
    fire({
      id: "cross-domain-redirects", category: "behavior", severity: "medium",
      title: "Redirect crosses multiple unrelated domains",
      detail: `Visited ${chainRoots.size} different domains before landing here.`,
      weight: 10, confidence: 0.8,
    });
  }

  // --- reputation: external APIs (best-effort, network-bounded) ---
  const sb = await checkGoogleSafeBrowsing(url, settings?.apiKeys?.googleSafeBrowsing);
  if (!sb.skipped && sb.malicious) {
    fire({
      id: "gsb", category: "reputation", severity: "critical",
      title: "Flagged by Google Safe Browsing",
      detail: `Threat types: ${(sb.threats || []).join(", ") || "unspecified"}`,
      weight: 90, confidence: 1,
    });
  }
  const vt = await checkVirusTotal(url, settings?.apiKeys?.virusTotal);
  if (!vt.skipped && vt.malicious) {
    const malCount = vt.stats?.malicious || 0;
    fire({
      id: "vt", category: "reputation", severity: "critical",
      title: "Flagged by VirusTotal engines",
      detail: `${malCount} engine(s) reported this URL as malicious.`,
      weight: 80, confidence: Math.min(1, 0.4 + malCount * 0.15),
    });
  }

  // --- clone-website detection (DOM-based, only when content provides it) ---
  // Pre-compute root reputation so clone weighting can adapt.
  const _isReputableEarly = KNOWN_REPUTABLE_ROOTS.has(root);
  const _isTrustedEarly = TRUSTED_LOGIN_PROVIDERS.has(root);
  const _trustedEarly = _isReputableEarly || _isTrustedEarly;
  let clone = null;
  if (pageContext && settings?.detection?.cloneDetection !== false) {
    clone = analyzeClone(pageContext);
    if (clone.confidence >= 0.4) {
      // On reputable / trusted roots, visual similarity is expected
      // (e.g. github.com loads assets from githubassets.com). Surface
      // it as informational only — do not subtract trust.
      const trustedClone = _trustedEarly && !clone.brandImageMismatch;
      fire({
        id: "clone", category: "clone",
        severity: trustedClone
          ? "info"
          : (clone.confidence >= 0.8 ? "critical" : "high"),
        title: trustedClone
          ? "Page shares layout characteristics with known providers"
          : "Page resembles a cloned brand site",
        detail: trustedClone
          ? "No credential theft behavior detected; visual similarity alone is not actionable on a known root."
          : clone.reasons.join("; "),
        weight: trustedClone ? 0 : 35,
        confidence: clone.confidence,
      });
    }
  }

  // --- phishing / credential-harvest (DOM-based) ---
  let phishing = null;
  if (pageContext) {
    phishing = analyzePhishing(pageContext);
    for (const s of phishing.signals) {
      if ((s.weight || 0) > 0) fire(s);
      else pass(s);
    }
    if (phishing.authRisk && phishing.authRisk !== "none") {
      pass({ id: "auth-risk", category: "behavior", severity: phishing.authRisk === "low" ? "info" : phishing.authRisk,
        title: `Authentication risk: ${phishing.authRisk}`,
        detail: "Auth workflows are evaluated with a conservative trust baseline." });
    }
  }

  // --- behavioral: authFlow anomalies (Issue NEW-02 wiring) ---
  // The authFlow snapshot is built locally in the content script (see
  // buildAuthFlowSnapshot) from already-collected DOM facts. We surface each
  // anomaly as a fired signal so it: (a) reaches arbitration via the
  // behavioral rule registry, (b) feeds trustDecay() on trusted roots, and
  // (c) appears in the popup explanation. Brand-agnostic; never references
  // secret values.
  const authFlow = ctx.authFlow || null;
  if (authFlow && Array.isArray(authFlow.anomalies)) {
    const AUTHFLOW_WEIGHT = {
      "credential-relay": 50,
      "oauth-token-drift": 35,
      "iframe-origin-swap": 28,
      "mfa-origin-split": 20,
      "redirect-storm": 14,
    };
    for (const a of authFlow.anomalies) {
      const w = AUTHFLOW_WEIGHT[a.id];
      if (!w) continue;
      fire({
        id: `authflow:${a.id}`, category: "behavior",
        severity: a.severity === "high" ? "high"
                : a.severity === "medium" ? "medium" : "low",
        title: humanAuthFlowTitle(a.id),
        detail: a.explain || "",
        weight: w, confidence: 0.9,
      });
    }
  }

  // --- trust signals (positive) ---
  let trustFloor = 0;
  let trustReasons = [];
  if ((settings?.allowlist || []).includes(root)) {
    trustFloor = Math.max(trustFloor, 85);
    trustReasons.push("on your allowlist");
    pass({ id: "allowlist", category: "trust", severity: "info",
      title: "You marked this domain as trusted." });
  }
  const stat = safeDomainStats?.[root];
  if (stat && stat.trustCount >= 3) {
    // After 3+ session trusts, learn the domain — soften scoring.
    trustFloor = Math.max(trustFloor, 70);
    trustReasons.push(`learned safe after ${stat.trustCount} session approvals`);
    pass({ id: "learned-safe", category: "trust", severity: "info",
      title: "Kedayam has learned to trust this domain.",
      detail: `You've approved this site ${stat.trustCount} times in past sessions.` });
  }

  // --- compute score: "unknown until trust is earned" ---
  // Start from a neutral baseline. Known reputable roots, HTTPS, learned
  // safety, and the absence of authentication risk *earn* trust additively.
  // Phishing / clone / lookalike penalties subtract. Hard arbitration rules
  // then cap the final score regardless of how many soft positives fired.
  const allowlistRoot = (settings?.allowlist || []).includes(root);
  const isReputableRoot = KNOWN_REPUTABLE_ROOTS.has(root);
  const isTrustedProvider = TRUSTED_LOGIN_PROVIDERS.has(root);
  const idnSpoof = lookalike.match?.kind === "punycode" || /(^|\.)xn--/i.test(host);
  const hasAuthWorkflow = !!pageContext && (
    phishing?.credentialHarvest || phishing?.authRisk === "medium" ||
    phishing?.authRisk === "high" || phishing?.authRisk === "critical" ||
    pageContext.hasPasswordField ||
    (pageContext.forms || []).some((f) => f.hasPassword || (f.hasEmailLike && f.hasOtp))
  );

  const BASELINE = 50;
  if (parsed.protocol === "https:") {
    addTrust({ id: "https-trust", title: "Encrypted connection (HTTPS)",
      points: 10 });
  }
  if (isReputableRoot) {
    addTrust({ id: "known-reputable", title: "Known reputable domain",
      detail: `${root} is on Kedayam's reputable-roots list.`, points: 28 });
  } else if (isTrustedProvider) {
    // Trusted provider corroboration — soft add only.
    addTrust({ id: "trusted-provider", title: "Recognized identity provider",
      detail: `${root} is a known sign-in provider.`, points: 14 });
  }
  if (allowlistRoot) {
    addTrust({ id: "allowlist-trust", title: "On your allowlist",
      points: 40 });
  }
  if (stat && stat.trustCount >= 3) {
    const bonus = Math.min(20, 8 + stat.trustCount * 2);
    addTrust({ id: "learned-safe-trust", title: "Learned-safe history",
      detail: `Approved ${stat.trustCount} times.`, points: bonus });
  }
  if (!hasAuthWorkflow && parsed.protocol === "https:") {
    addTrust({ id: "no-auth-risk", title: "No authentication workflow detected",
      points: 5 });
  }
  if (typeof domainAgeDays === "number" && domainAgeDays > 365) {
    addTrust({ id: "established-domain",
      title: `Domain established (${Math.round(domainAgeDays / 365)}y old)`,
      points: 6 });
  }

  const trustGain = trustAdds.reduce((a, s) => a + s.contribution, 0);
  const penalty = fired.reduce((acc, s) => acc + s.contribution, 0); // negative
  let score = BASELINE + trustGain + penalty;

  // Soft pre-cap: an unknown root presenting an auth workflow can never
  // accidentally cross into "safe" without strong corroboration.
  if (hasAuthWorkflow && !isReputableRoot && !allowlistRoot && !isTrustedProvider) {
    score = Math.min(score, 65);
  }

  score = Math.max(0, Math.min(100, score));
  if (trustFloor) score = Math.max(score, trustFloor);

  // --- deterministic arbitration ---
  // authFlow anomalies fold into the same arbitration inputs that already
  // drive external-POST / iframe-credential / oauth-spoof rules — so the
  // behavioral subsystem materially affects caps and force-status, not just
  // diagnostics. (Issue NEW-02.)
  const _authAnoms = (authFlow?.anomalies) || [];
  const _authHas = (id) => _authAnoms.some((a) => a.id === id);
  const _phishingForArb = {
    ...(phishing || {}),
    externalFormPost: !!(phishing?.externalFormPost || _authHas("credential-relay")),
    oauthSpoof: !!(phishing?.oauthSpoof || _authHas("oauth-token-drift")),
    signals: [
      ...((phishing?.signals) || []),
      ...(_authHas("iframe-origin-swap") ? [{ id: "iframe-credential-form" }] : []),
    ],
  };

  // --- Contextual dampening (security-research / educational pages) ---
  // Reduces VISUAL/TEXTUAL false positives on legitimate pages that discuss
  // phishing, host benign demo auth content, or document OAuth flows.
  // Behavioral evidence bypasses this entirely (computed below) — we never
  // dampen external POST, cross-origin creds, OAuth spoof, MFA harvest,
  // threat-intel hits, or auth-flow anomalies.
  const _earlyPhishSigs = _phishingForArb.signals || [];
  const _earlyHasSig = (id) => _earlyPhishSigs.some((s) => s.id === id);
  const _behavioralEvidenceEarly = !!(
    _phishingForArb.externalFormPost || _phishingForArb.oauthSpoof ||
    _earlyHasSig("iframe-credential-form") || _earlyHasSig("iframe-login") ||
    (sb && sb.malicious) || (vt && vt.malicious) ||
    _authHas("credential-relay") || _authHas("oauth-token-drift") ||
    _authHas("iframe-origin-swap")
  );
  const secContext = analyzeSecurityContext({
    host, path: parsed.pathname, pageContext,
  });
  let dampening = 0;
  let lookalikeForArb = lookalike;
  let cloneForArb = clone || {};
  let phishingForArb = _phishingForArb;
  if (secContext.score >= SECURITY_CONTEXT_THRESHOLD &&
      !_behavioralEvidenceEarly && !allowlistRoot) {
    dampening = secContext.score;
    lookalikeForArb = {
      ...lookalike,
      confidence: dampenConfidence(lookalike.confidence, dampening),
    };
    cloneForArb = {
      ...cloneForArb,
      confidence: dampenConfidence(cloneForArb.confidence, dampening),
    };
    // Strip text-only impersonation flags + visual-only caps. Behavioral
    // flags (externalFormPost, oauthSpoof, iframe-credential-form,
    // credentialHarvest with real password fields) are preserved.
    phishingForArb = {
      ..._phishingForArb,
      brandImpersonation: false,
      confidence: dampenConfidence(_phishingForArb.confidence || 0, dampening),
      // Visual-only forced status from phishing heuristics must not stand
      // on educational pages without behavioral corroboration.
      forceStatus: _phishingForArb.externalFormPost || _phishingForArb.oauthSpoof
        ? _phishingForArb.forceStatus
        : null,
      cap: _phishingForArb.externalFormPost || _phishingForArb.oauthSpoof
        ? _phishingForArb.cap
        : null,
    };
    // Offset the visual-only penalty already applied to `score` via fired
    // signals (lookalike, clone, brand-text). The offset is bounded and
    // never raises an unknown auth page out of suspicious territory because
    // the soft pre-cap (line ~387) is still applied below.
    const visualPenalty = fired
      .filter((s) => s.id === "lookalike" || s.id === "clone" ||
                     s.id === "brand-impersonation" || s.id === "auth-layout-clone")
      .reduce((a, s) => a + Math.abs(s.contribution), 0);
    const offset = Math.round(Math.min(visualPenalty, 30) * dampening * 0.8);
    if (offset > 0) {
      addTrust({
        id: "security-context",
        title: "Security-research / educational context",
        detail: `Visual heuristics softened — ${secContext.reasons.join("; ") || "context signals"}.`,
        points: offset,
      });
    } else {
      // Surface even with zero offset so audit trail captures the decision.
      pass({
        id: "security-context", category: "trust", severity: "info",
        title: "Security-research / educational context",
        detail: `Visual heuristics softened pending behavioral evidence — ${secContext.reasons.join("; ") || "context signals"}.`,
      });
    }
  }

  const arb = arbitrate({
    allowlistRoot, isReputableRoot, isTrustedProvider, hasAuthWorkflow,
    lookalike: lookalikeForArb, idnSpoof, clone: cloneForArb,
    phishing: phishingForArb,
    gsbMalicious: !!(sb && sb.malicious),
    vtMalicious: !!(vt && vt.malicious),
  });
  // Apply arbitration caps unconditionally. The allowlist primitive raises
  // the floor and silences weak heuristics inside arbitrate(), but it MUST
  // NOT bypass active behavioral evidence (Issue C-02). If arbitration
  // produced rules under an allowlisted root, those rules represent
  // exfiltration evidence and must score the page accordingly.
  if (arb.cap != null) score = Math.min(score, arb.cap);
  for (const cap of scoreCaps) score = Math.min(score, cap.maxScore);
  // phishing.cap / phishing.forceStatus may come from weak text signals
  // (e.g. brand-impersonation phrasing). The allowlist suppresses those
  // weak heuristics, but NEVER suppresses behavioral evidence (external
  // POST, cross-origin creds, OAuth spoof, threat-intel).
  const phishSigs = phishing?.signals || [];
  const hasPhishSig = (id) => phishSigs.some((s) => s.id === id);
  const maliciousBehavior = !!(phishing?.externalFormPost ||
    hasPhishSig("iframe-credential-form") || hasPhishSig("iframe-login") ||
    phishing?.oauthSpoof || (sb && sb.malicious) || (vt && vt.malicious));
  if (!allowlistRoot || maliciousBehavior) {
    if (phishing?.cap != null) score = Math.min(score, phishing.cap);
  }
  if (arb.trustFloor != null && parsed.protocol === "https:") {
    score = Math.max(score, arb.trustFloor);
  }

  // --- M3: trust anomaly decay on trusted/reputable/allowlisted roots ---
  const trustedRoot = isReputableRoot || isTrustedProvider || allowlistRoot;
  const behavioralEvidence = !!(phishing?.externalFormPost ||
    phishing?.oauthSpoof || hasPhishSig("iframe-credential-form") ||
    hasPhishSig("iframe-login") || (sb && sb.malicious) ||
    (vt && vt.malicious) ||
    _authHas("credential-relay") || _authHas("oauth-token-drift") ||
    _authHas("iframe-origin-swap"));
  const decay = trustDecay({
    trustedRoot, behavioralEvidence,
    arbitration: arb, phishing: phishing || {},
    authFlow: ctx.authFlow || null,
    hiddenLoginOverlay: !!ctx.hiddenLoginOverlay,
    cspWeakened: !!ctx.cspWeakened,
  });
  if (decay.delta > 0) {
    score = Math.max(0, score - decay.delta);
    if (decay.floorOverride != null) {
      score = Math.min(score, Math.max(decay.floorOverride, score));
    }
  }

  let status = score >= 71 ? "safe" : score >= 41 ? "suspicious" : "dangerous";
  const arbForce = arb.forceStatus;
  const phishForce = (!allowlistRoot || maliciousBehavior)
    ? phishing?.forceStatus : null;
  const forceStatus = arbForce || phishForce;
  if (forceStatus) {
    const order = { safe: 0, suspicious: 1, dangerous: 2 };
    if (order[forceStatus] > order[status]) status = forceStatus;
  }

  // --- M2 / M5: progressive suspicion + arbitration trace ---
  const suspicion = deriveSuspicion({
    score, status, behavioralEvidence,
    anomalyDelta: decay.delta, trustedRoot,
  });
  const trace = buildArbitrationTrace({
    arbitration: arb, decay, suspicion, score,
    baselineScore: BASELINE + trustGain + penalty,
    trustedRoot, behavioralEvidence,
  });

  // --- human summary: pick top 2 contributors ---
  const topSignals = [...fired].sort((a, b) => a.contribution - b.contribution).slice(0, 2);
  const summary = buildSummary({ status, score, topSignals, trustReasons, host });

  // confidence in *the verdict itself* — high when many signals agree or one strong one fires
  const totalConfidence = fired.length
    ? Math.min(1, fired.reduce((a, s) => a + s.confidence * Math.min(1, s.weight / 30), 0) / 1.5)
    : 0.6;

  // Phishing confidence — fired identity/structure/reputation signals.
  const phishingCats = new Set(["identity", "structure", "behavior", "reputation", "clone"]);
  const phishingFired = fired.filter((s) => phishingCats.has(s.category));
  const phishingConfidence = round2(Math.min(1,
    phishingFired.reduce((a, s) => a + s.confidence * Math.min(1, s.weight / 25), 0) / 2));

  return {
    url, host, root, score, status,
    summary,
    confidence: round2(totalConfidence),
    phishingConfidence,
    cloneConfidence: round2(clone?.confidence || 0),
    authRisk: phishing?.authRisk || "none",
    signals: [...fired, ...trustAdds, ...scoreCaps, ...passed],
    trustAdds,
    arbitration: arb,
    trustDecay: decay,
    suspicion,
    trace,
    firedCount: fired.length,
    lookalike,
    clone,
    phishing,
    safeBrowsing: { google: sb, virusTotal: vt },
    evaluatedAt: Date.now(),
  };
}

function buildSummary({ status, score, topSignals, trustReasons, host }) {
  if (status === "safe" && !topSignals.length) {
    const trust = trustReasons.length ? ` (${trustReasons.join(", ")})` : "";
    return `${host} looks safe${trust}.`;
  }
  if (!topSignals.length) return `${host} scored ${score}/100.`;
  const reasons = topSignals.map((s) => s.title.toLowerCase()).join(" and ");
  const verb = status === "dangerous" ? "is high risk because"
            : status === "suspicious" ? "looks unusual because"
            : "is mostly safe but note";
  return `${host} ${verb} of ${reasons}.`;
}

function clamp01(n) { return Math.max(0, Math.min(1, Number(n) || 0)); }
function round2(n) { return Math.round(n * 100) / 100; }

function humanAuthFlowTitle(id) {
  switch (id) {
    case "credential-relay":   return "Credentials would be sent off-flow";
    case "oauth-token-drift":  return "OAuth token arrives on an unrelated origin";
    case "iframe-origin-swap": return "Login is collected inside a foreign-origin iframe";
    case "mfa-origin-split":   return "Password and MFA collected on different origins";
    case "redirect-storm":     return "Authentication crossed many unrelated origins";
    default:                   return `Auth flow anomaly: ${id}`;
  }
}

function errorResult(url, message) {
  return {
    url, host: "", root: "",
    score: 50, status: "suspicious",
    summary: `Could not evaluate URL: ${message}`,
    confidence: 0,
    signals: [{ id: "error", category: "structure", severity: "medium",
      title: "Could not evaluate URL", detail: message,
      weight: 0, confidence: 0, contribution: 0 }],
    firedCount: 0,
    lookalike: { match: null, confidence: 0, reasons: [] },
    safeBrowsing: {}, evaluatedAt: Date.now(),
  };
}
