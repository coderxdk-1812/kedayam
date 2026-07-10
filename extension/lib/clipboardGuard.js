// Kedayam — ClickFix / "FakeCaptcha" clipboard-injection guard (freeware, local).
//
// THE dominant malware-distribution technique of 2024-2025. The page shows a
// fake CAPTCHA / "verify you are human" / "fix this error" prompt, silently
// writes a malicious OS command to the clipboard via navigator.clipboard
// .writeText(), and instructs the victim to press Win+R (or open Terminal) and
// paste. The pasted command pulls down and runs a stealer/loader.
//
// Antivirus rarely catches this because no file is downloaded by the browser —
// the user runs the payload themselves. A browser-side guard that inspects
// what a page just copied to the clipboard, and what it is *telling* the user
// to do, is uniquely positioned to stop it.
//
// This module is PURE: it classifies strings. It never executes, stores, or
// transmits anything. The content script feeds it (a) text a page wrote to the
// clipboard and (b) the page's visible instruction text, and renders a warning
// when the combination is dangerous. Raw values are redacted in any output.

// Command interpreters / LOLBins that have no business being on a clipboard a
// web page just populated.
const CMD_SIGNATURES = [
  { id: "powershell", re: /\b(powershell|pwsh)\b/i, label: "PowerShell" },
  {
    id: "ps-encoded",
    re: /-e(nc|ncodedcommand)?\b\s+[A-Za-z0-9+/=]{12,}/i,
    label: "encoded PowerShell command",
  },
  {
    id: "ps-iex",
    re: /\b(iex|invoke-expression|invoke-webrequest|invoke-restmethod|iwr|irm|downloadstring|downloadfile|frombase64string|start-bitstransfer|net\.webclient)\b/i,
    label: "PowerShell download-and-run",
  },
  {
    id: "ps-hidden",
    re: /-(w(indowstyle)?\s+hidden|nop|noprofile|noni|ep\s+bypass|executionpolicy\s+bypass)\b/i,
    label: "hidden PowerShell flags",
  },
  {
    id: "defender-evade",
    re: /\b(add-mppreference|set-mppreference|-exclusionpath|amsiutils|amsiinitfailed)\b/i,
    label: "antivirus-evasion command",
  },
  { id: "cmd", re: /\bcmd(\.exe)?\s*\/(c|k)\b/i, label: "Windows command shell" },
  { id: "mshta", re: /\bmshta(\.exe)?\b|hta:application|\.hta\b/i, label: "mshta script runner" },
  {
    id: "lolbin",
    re: /\b(certutil|bitsadmin|regsvr32|rundll32|wscript|cscript|msiexec|forfiles|installutil|schtasks|conhost|wmic|hh\.exe)\b/i,
    label: "Windows LOLBin",
  },
  {
    id: "nix-oneliner",
    re: /\b(python3?|node|perl|ruby)\s+-(c|e)\b[^\n]{0,200}(http|socket|urllib|requests|child_process|exec)/i,
    label: "scripting-language download-and-run",
  },
  {
    id: "curl-pipe",
    re: /\b(curl|wget)\b[^\n|]{0,200}\|\s*(ba)?sh\b/i,
    label: "curl/wget piped to a shell",
  },
  {
    id: "curl-iex",
    re: /\b(curl|wget|iwr)\b[^\n|]{0,200}\|\s*iex\b/i,
    label: "download piped to PowerShell",
  },
  {
    id: "base64-sh",
    re: /base64\s+(-d|--decode)\b[^\n|]{0,120}\|\s*(ba)?sh\b/i,
    label: "base64-decoded shell command",
  },
  { id: "osascript", re: /\bosascript\b|\bdo shell script\b/i, label: "macOS osascript" },
];

// Page instruction text that, paired with a clipboard write, screams ClickFix.
const RUN_DIALOG_PHRASES = [
  /\bwin(dows)?\s*\+\s*r\b/i,
  /\bpress\s+(the\s+)?(windows|win)\b.*\br\b/i,
  /\b(hold|press)\b.*\bwindows\s*key\b.*\br\b/i,
  /⊞/, // the Windows-key glyph, common in ClickFix step graphics
  /\b(open|launch)\s+(the\s+)?(run\s+dialog|run\s+(box|window)|powershell|terminal|command\s+prompt|cmd)\b/i,
  /\bctrl\s*\+\s*v\b.*\b(enter|run)\b/i,
  /\bpaste\b.*\b(and\s+)?(press|hit)\s+(enter|return)\b/i,
  /\bpaste\s+(this|the\s+(code|command|script)|it)\b/i,
  /\b(open|launch|press)\s+(spotlight|terminal|finder)\b/i,
  /\b(command|⌘)\s*(\+|key\s+and)\s*(space|spacebar)\b/i,
  /\btype\s+(in\s+)?terminal\b/i,
];
const FAKE_VERIFY_PHRASES = [
  /\bverify\s+(you('| a)?re|that you are)\s+(a\s+)?human\b/i,
  /\bi('| a)?m not a robot\b/i,
  /\b(human|robot)\s+verification\b/i,
  /\bverification\s+(steps|failed|required|id)\b/i,
  /\bto (continue|proceed),?\s+(please\s+)?(complete|perform|follow)\b/i,
  /\bchecking\s+(if\s+)?your\s+browser\b/i,
  /\bray\s*id\b/i, // fake Cloudflare "Ray ID" chrome
  /\bcaptcha\b/i,
];

// Safe value written over the clipboard when neutralizing a ClickFix command, so
// the planted command cannot be pasted-and-run even by accident. Exported so the
// content script and its tests share one definition.
export const SAFE_CLIPBOARD_TEXT = "[cleared by Kedayam — a malicious command was removed]";

function redactCommand(s) {
  const t = String(s || "")
    .replace(/\s+/g, " ")
    .trim();
  if (t.length <= 48) return t;
  return t.slice(0, 45) + "…";
}

/**
 * Classify a string a web page just wrote to the clipboard.
 * @param {string} text
 * @returns {{ malicious:boolean, confidence:number, technique:string|null,
 *             label:string|null, preview:string }}
 */
export function classifyClipboardWrite(text) {
  const out = { malicious: false, confidence: 0, technique: null, label: null, preview: "" };
  if (typeof text !== "string") return out;
  const s = text.slice(0, 8000);
  if (s.length < 6) return out;

  const hits = [];
  for (const sig of CMD_SIGNATURES) {
    if (sig.re.test(s)) hits.push(sig);
  }
  if (!hits.length) return out;

  // A bare "powershell" word is weaker than "powershell -enc <blob>" or a
  // download-and-run chain. Confidence scales with how many independent
  // command signatures corroborate, and which ones.
  const strong = hits.some((h) =>
    [
      "ps-encoded",
      "ps-iex",
      "ps-hidden",
      "defender-evade",
      "mshta",
      "curl-pipe",
      "curl-iex",
      "base64-sh",
      "lolbin",
      "nix-oneliner",
    ].includes(h.id),
  );
  const conf = strong
    ? Math.min(0.98, 0.85 + (hits.length - 1) * 0.05)
    : Math.min(0.8, 0.5 + (hits.length - 1) * 0.1);

  out.malicious = true;
  out.confidence = conf;
  out.technique = hits.map((h) => h.id).join(",");
  out.label = hits[0].label;
  out.preview = redactCommand(s);
  return out;
}

/**
 * Classify a page's visible instruction text for ClickFix social engineering.
 * Used to corroborate (or independently surface) the run-dialog lure even when
 * the clipboard write is deferred until the user clicks.
 * @param {string} text
 * @returns {{ clickFixInstructions:boolean, fakeVerify:boolean, confidence:number }}
 */
export function classifyInstructionText(text) {
  const out = { clickFixInstructions: false, fakeVerify: false, confidence: 0 };
  if (typeof text !== "string" || !text) return out;
  const s = text.slice(0, 20000);
  const runDialog = RUN_DIALOG_PHRASES.some((re) => re.test(s));
  const fakeVerify = FAKE_VERIFY_PHRASES.some((re) => re.test(s));
  out.clickFixInstructions = runDialog;
  out.fakeVerify = fakeVerify;
  // Run-dialog instructions are the load-bearing signal; fake-verify alone is
  // common on legit sites (real CAPTCHAs) and must not warn by itself.
  out.confidence = runDialog ? (fakeVerify ? 0.95 : 0.8) : 0;
  return out;
}

/**
 * Combine a clipboard write with page instructions into a single verdict the
 * content script can act on.
 * @returns {{ severity:'critical'|'high'|'none', confidence:number,
 *             label:string|null, preview:string, reason:string }}
 */
export function assessClickFix(clipboardText, instructionText) {
  const clip = classifyClipboardWrite(clipboardText);
  const instr = classifyInstructionText(instructionText);
  if (clip.malicious) {
    // A page wrote an OS command to the clipboard. That is almost never
    // legitimate; instructions to run it push confidence to the ceiling.
    const corroborated = instr.clickFixInstructions || instr.fakeVerify;
    return {
      severity: "critical",
      confidence: Math.min(0.99, clip.confidence + (corroborated ? 0.05 : 0)),
      label: clip.label,
      preview: clip.preview,
      reason: corroborated
        ? "This page copied a system command to your clipboard and is telling you to run it (ClickFix malware)."
        : "This page silently copied a system command to your clipboard.",
    };
  }
  if (instr.clickFixInstructions && instr.fakeVerify) {
    // Strong textual ClickFix lure without a captured clipboard write (e.g.
    // the write happens on a later click). Surface as high, not critical.
    return {
      severity: "high",
      confidence: instr.confidence,
      label: null,
      preview: "",
      reason:
        "This page is using fake-verification steps that ask you to paste and run a command — a common malware trick.",
    };
  }
  return { severity: "none", confidence: 0, label: null, preview: "", reason: "" };
}

export const _internal = { CMD_SIGNATURES, RUN_DIALOG_PHRASES, FAKE_VERIFY_PHRASES, redactCommand };
