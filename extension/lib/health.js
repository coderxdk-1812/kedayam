// Kedayam — extension health monitor. Counters live in memory; the popup
// can ask for a snapshot. We keep this deliberately tiny — anything bigger
// risks becoming "telemetry" which violates the privacy posture.

export class HealthMonitor {
  constructor() {
    this.counters = Object.create(null);
    this.startedAt = Date.now();
    this.lastError = null;
  }
  inc(name, by = 1) {
    this.counters[name] = (this.counters[name] || 0) + by;
    return this.counters[name];
  }
  recordError(err, where) {
    this.lastError = {
      where: String(where || "unknown"),
      message: String(err?.message || err).slice(0, 300),
      at: Date.now(),
    };
    this.inc("errors");
  }
  snapshot() {
    return {
      uptimeMs: Date.now() - this.startedAt,
      counters: { ...this.counters },
      lastError: this.lastError,
    };
  }
}
