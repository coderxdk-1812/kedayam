// Kedayam — IDN mixed-script / confusable hostname detection (local, pure).
//
// Homoglyph mapping (lookalike.js) catches a Unicode host that *decodes* to a
// known brand. But the canonical, near-zero-false-positive IDN-spoofing tell is
// a hostname *label that mixes Unicode scripts* — e.g. a Latin "a" swapped for a
// Cyrillic "а" inside an otherwise-Latin word ("аpple.com"). Legitimate
// internationalized domains are written in ONE script per label; an attacker
// mixing Latin with Cyrillic/Greek/Armenian to fake a Latin brand is the giveaway.
//
// This module classifies the script of each character and flags labels that
// combine letters from more than one script. It is deliberately conservative:
// common characters (digits, hyphen) are ignored, and a single-script non-Latin
// label (a genuine IDN) is NOT flagged here — that case is left to the homoglyph
// brand matcher in lookalike.js.

import { toUnicodeHost } from "./lookalike.js";

// Minimal script classifier covering the scripts actually abused for Latin-brand
// spoofing. Returns a script tag or "common" for digits / hyphen / dot.
function scriptOf(cp) {
  if (cp === 0x2d || cp === 0x2e) return "common"; // - .
  if (cp >= 0x30 && cp <= 0x39) return "common"; // 0-9
  if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a)) return "latin";
  if (cp >= 0x00c0 && cp <= 0x024f) return "latin"; // Latin-1 supp + extended
  if (cp >= 0x0400 && cp <= 0x052f) return "cyrillic";
  if ((cp >= 0x0370 && cp <= 0x03ff) || (cp >= 0x1f00 && cp <= 0x1fff)) return "greek";
  if (cp >= 0x0530 && cp <= 0x058f) return "armenian";
  if (cp >= 0x0590 && cp <= 0x05ff) return "hebrew";
  if (cp >= 0x0600 && cp <= 0x06ff) return "arabic";
  if (cp >= 0x0e00 && cp <= 0x0e7f) return "thai";
  if (cp >= 0x4e00 && cp <= 0x9fff) return "han";
  if (cp >= 0xac00 && cp <= 0xd7a3) return "hangul";
  return "other";
}

// Scripts that, when mixed WITH Latin in the same label, indicate a spoof of a
// Latin-script brand. (Latin+Han, e.g. a real CJK brand with an ASCII word, is
// far more likely legitimate, so we don't escalate those combinations.)
const SPOOF_SCRIPTS = new Set(["cyrillic", "greek", "armenian"]);

/**
 * @param {string} hostname
 * @returns {{
 *   mixedScript: boolean,
 *   scripts: string[],
 *   label: string|null,
 *   confidence: number,
 *   signals: Array<object>,
 * }}
 */
export function analyzeConfusable(hostname) {
  const out = { mixedScript: false, scripts: [], label: null, confidence: 0, signals: [] };
  if (!hostname || typeof hostname !== "string") return out;

  // Work on the decoded Unicode form so xn-- labels are evaluated as glyphs.
  const unicodeHost = toUnicodeHost(hostname);
  const labels = unicodeHost.split(".");

  for (const label of labels) {
    const present = new Set();
    for (const ch of label) {
      const s = scriptOf(ch.codePointAt(0));
      if (s !== "common") present.add(s);
    }
    if (present.size < 2) continue;
    const scripts = [...present];
    const hasLatin = present.has("latin");
    const spoofMix = hasLatin && scripts.some((s) => SPOOF_SCRIPTS.has(s));
    out.mixedScript = true;
    out.scripts = scripts;
    out.label = label;
    out.confidence = spoofMix ? 0.95 : 0.75;
    out.signals.push({
      id: "mixed-script-host",
      category: "identity",
      severity: spoofMix ? "critical" : "high",
      title: "Hostname mixes multiple alphabets",
      detail: spoofMix
        ? `The label "${label}" combines Latin with ${scripts.filter((s) => SPOOF_SCRIPTS.has(s)).join("/")} characters — a classic look-alike trick to fake a real brand.`
        : `The label "${label}" mixes ${scripts.join(" + ")} scripts, which is unusual for a legitimate domain.`,
      weight: spoofMix ? 45 : 28,
      confidence: out.confidence,
    });
    break; // one mixed label is enough to flag the host
  }

  return out;
}

export const _internal = { scriptOf, SPOOF_SCRIPTS };
