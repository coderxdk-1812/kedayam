import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { BIAS, WEIGHTS, CLASSIFIER_META } from "../../extension/lib/rules/classifierWeights.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const evalReport = JSON.parse(
  readFileSync(path.resolve(__dirname, "../../public/kedayam-classifier-eval.json"), "utf8"),
);

describe("fitted classifier weights", () => {
  it("has a numeric bias and non-negative monotonic weights", () => {
    expect(typeof BIAS).toBe("number");
    // Every feature can only RAISE phishing risk — no negative weights.
    for (const [, w] of Object.entries(WEIGHTS)) {
      expect(typeof w).toBe("number");
      expect(w).toBeGreaterThanOrEqual(0);
    }
  });

  it("carries measured metrics from a real labeled corpus", () => {
    expect(CLASSIFIER_META.corpus.phishing).toBeGreaterThan(1000);
    expect(CLASSIFIER_META.corpus.benign).toBeGreaterThan(1000);
    const warn = CLASSIFIER_META.metrics.warn;
    // Measured, not a placeholder: sane precision/recall/FP.
    expect(warn.precision).toBeGreaterThan(0.9);
    expect(warn.recall).toBeGreaterThan(0.3);
    expect(warn.falsePositiveRate).toBeLessThan(0.05);
  });

  it("keeps the fixed runtime priors present", () => {
    for (const k of CLASSIFIER_META.fixedPriorFeatures) {
      expect(WEIGHTS[k]).toBeGreaterThan(0);
    }
  });

  it("the shipped eval report matches the model metadata", () => {
    expect(evalReport.warn.precision).toBe(CLASSIFIER_META.metrics.warn.precision);
    expect(evalReport.warn.recall).toBe(CLASSIFIER_META.metrics.warn.recall);
    expect(evalReport.corpus.phishing).toBe(CLASSIFIER_META.corpus.phishing);
  });
});
