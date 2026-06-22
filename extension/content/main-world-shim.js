// Kedayam — MAIN-world shim. Injected via <script src> (no inline code) so
// it complies with strict MV3 / page CSPs. Hooks a few sensitive web APIs and
// posts a CustomEvent back to the isolated content script.
(() => {
  if (window.__kedayamShim) return;
  window.__kedayamShim = true;
  const post = (what) =>
    window.dispatchEvent(new CustomEvent("kedayam:perm", { detail: { what } }));

  try {
    const md = navigator.mediaDevices;
    if (md && md.getUserMedia) {
      const orig = md.getUserMedia.bind(md);
      md.getUserMedia = (c) => {
        post(c?.video ? "camera" : c?.audio ? "microphone" : "device");
        return orig(c);
      };
    }
  } catch {}

  try {
    const g = navigator.geolocation;
    if (g?.getCurrentPosition) {
      const orig = g.getCurrentPosition.bind(g);
      g.getCurrentPosition = (...a) => {
        post("location");
        return orig(...a);
      };
    }
    if (g?.watchPosition) {
      const orig = g.watchPosition.bind(g);
      g.watchPosition = (...a) => {
        post("location");
        return orig(...a);
      };
    }
  } catch {}

  try {
    if (navigator.clipboard?.readText) {
      const orig = navigator.clipboard.readText.bind(navigator.clipboard);
      navigator.clipboard.readText = (...a) => {
        post("clipboard");
        return orig(...a);
      };
    }
  } catch {}

  // ClickFix / FakeCaptcha defense: observe what a page WRITES to the
  // clipboard. The dominant 2024-2025 malware lure silently copies an OS
  // command (powershell/mshta/curl|bash) and tells the victim to paste+run it.
  // We post the written text (truncated) back to the isolated content script
  // for local classification. The page already has this text — nothing is
  // leaked — and it is never stored or transmitted off-device.
  const postClip = (text) => {
    try {
      window.dispatchEvent(
        new CustomEvent("kedayam:clip", {
          detail: { text: String(text == null ? "" : text).slice(0, 8000) },
        }),
      );
    } catch {}
  };
  try {
    if (navigator.clipboard?.writeText) {
      const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = (text) => {
        postClip(text);
        return orig(text);
      };
    }
  } catch {}
  // Legacy execCommand('copy') path — capture the current selection's text.
  try {
    const origExec = document.execCommand.bind(document);
    document.execCommand = (cmd, ...rest) => {
      try {
        if (typeof cmd === "string" && cmd.toLowerCase() === "copy") {
          const sel = (window.getSelection && window.getSelection().toString()) || "";
          if (sel) postClip(sel);
        }
      } catch {}
      return origExec(cmd, ...rest);
    };
  } catch {}
})();
