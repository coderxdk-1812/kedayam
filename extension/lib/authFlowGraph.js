// Kedayam — Auth Flow Graph (M1)
//
// Short-lived, in-memory graph that tracks the *behavioral shape* of an
// authentication flow without ever capturing the credentials themselves.
// Used to detect:
//
//   - AiTM (adversary-in-the-middle) relay patterns
//   - impossible / inconsistent auth transitions
//   - cross-origin credential hand-offs
//   - OAuth continuation drift (token returned to a 3rd-party origin)
//   - iframe auth boundaries that change origin mid-flow
//
// Guarantees:
//   - graphs are entirely local to the content-script tab
//   - no node ever stores a password, OTP code, or token value
//   - nodes auto-expire after `TTL_MS`
//   - the graph is bounded (MAX_NODES); oldest evicted FIFO
//   - calling `serialize()` returns a redacted, JSON-safe summary

const TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_NODES = 64;

/** @typedef {"entry"|"credential"|"mfa"|"oauth"|"redirect"|"token"|"iframe"} StepKind */

/**
 * @typedef {Object} FlowStep
 * @property {string}   id
 * @property {StepKind} kind
 * @property {string}   origin      // page origin at this step
 * @property {string}   [postOrigin] // form action / redirect target origin
 * @property {boolean}  [inIframe]
 * @property {number}   t           // monotonic ms timestamp
 * @property {string[]} [tags]
 */

export class AuthFlowGraph {
  constructor({ now = () => Date.now() } = {}) {
    this._now = now;
    /** @type {FlowStep[]} */ this._steps = [];
    this._gen = 0;
  }

  _gc() {
    const cutoff = this._now() - TTL_MS;
    this._steps = this._steps.filter((s) => s.t >= cutoff);
    while (this._steps.length > MAX_NODES) this._steps.shift();
  }

  /** Record a behavioral step. Never accepts secret values. */
  record(kind, info = {}) {
    this._gc();
    if (info && (info.password || info.otp || info.token || info.value)) {
      // Defensive: refuse to store anything that looks like a secret.
      // The caller has a bug if it tries.
      throw new Error("AuthFlowGraph.record: secret values are forbidden");
    }
    /** @type {FlowStep} */
    const step = {
      id: `s${++this._gen}`,
      kind,
      origin: safeOrigin(info.origin),
      postOrigin: info.postOrigin ? safeOrigin(info.postOrigin) : undefined,
      inIframe: !!info.inIframe,
      t: this._now(),
      tags: Array.isArray(info.tags) ? info.tags.slice(0, 6) : undefined,
    };
    this._steps.push(step);
    return step;
  }

  steps() {
    this._gc();
    return this._steps.slice();
  }

  reset() {
    this._steps = [];
    this._gen = 0;
  }

  /**
   * Pure analytical pass — returns anomaly objects, never throws.
   * Anomalies are *behavioral*: they never reference brands or branding.
   */
  anomalies() {
    this._gc();
    const out = [];
    const steps = this._steps;
    if (steps.length < 2) return out;

    const origins = new Set(steps.map((s) => s.origin).filter(Boolean));
    const credSteps = steps.filter((s) => s.kind === "credential" || s.kind === "mfa");
    const postOrigins = new Set(credSteps.map((s) => s.postOrigin).filter(Boolean));

    // a. Credentials POSTed to an origin never visited in-flow.
    for (const p of postOrigins) {
      if (p && !origins.has(p)) {
        out.push({
          id: "credential-relay",
          severity: "high",
          explain: `Credential step targets ${p}, which is not part of the visited auth flow.`,
        });
      }
    }

    // b. OAuth continuation drift — token step on an origin different from
    // every prior oauth-issuer origin.
    const oauthOrigins = steps.filter((s) => s.kind === "oauth").map((s) => s.origin);
    const tokenOrigins = steps.filter((s) => s.kind === "token").map((s) => s.origin);
    if (oauthOrigins.length && tokenOrigins.length) {
      const issuerSet = new Set(oauthOrigins);
      if (tokenOrigins.some((o) => !issuerSet.has(o))) {
        out.push({
          id: "oauth-token-drift",
          severity: "high",
          explain: "OAuth token arrives on an origin different from the issuer.",
        });
      }
    }

    // c. Iframe auth boundary swap — credential step inside a different
    // origin than the parent entry origin.
    const entry = steps.find((s) => s.kind === "entry");
    if (entry) {
      for (const cs of credSteps) {
        if (cs.inIframe && cs.origin && cs.origin !== entry.origin) {
          out.push({
            id: "iframe-origin-swap",
            severity: "medium",
            explain: `Credential entry happens inside an iframe on ${cs.origin}, embedded under ${entry.origin}.`,
          });
          break;
        }
      }
    }

    // d. Impossibly long redirect chain through unrelated origins.
    const redirects = steps.filter((s) => s.kind === "redirect");
    const redirectOrigins = new Set(redirects.map((s) => s.origin));
    if (redirectOrigins.size >= 4) {
      out.push({
        id: "redirect-storm",
        severity: "medium",
        explain: `Auth flow crossed ${redirectOrigins.size} unrelated origins.`,
      });
    }

    // e. MFA step on a different origin than the password step.
    const pw = credSteps.find((s) => s.kind === "credential");
    const mfa = credSteps.find((s) => s.kind === "mfa");
    if (pw && mfa && pw.origin && mfa.origin && pw.origin !== mfa.origin) {
      out.push({
        id: "mfa-origin-split",
        severity: "medium",
        explain: `Password collected on ${pw.origin}, MFA collected on ${mfa.origin}.`,
      });
    }

    return out;
  }

  /** Redacted, JSON-safe shape suitable for diagnostics. */
  serialize() {
    this._gc();
    return {
      steps: this._steps.map((s) => ({
        id: s.id,
        kind: s.kind,
        origin: s.origin,
        postOrigin: s.postOrigin,
        inIframe: s.inIframe,
        t: s.t,
        tags: s.tags,
      })),
      anomalies: this.anomalies(),
    };
  }
}

function safeOrigin(o) {
  if (!o) return "";
  try {
    return new URL(o).origin;
  } catch {
    return String(o).slice(0, 200);
  }
}

/** Singleton helper — most callers want one graph per tab/session. */
let _shared = null;
export function sharedAuthFlowGraph() {
  if (!_shared) _shared = new AuthFlowGraph();
  return _shared;
}
export function resetSharedAuthFlowGraph() {
  _shared = null;
}
