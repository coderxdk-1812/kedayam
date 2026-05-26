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
      g.getCurrentPosition = (...a) => { post("location"); return orig(...a); };
    }
    if (g?.watchPosition) {
      const orig = g.watchPosition.bind(g);
      g.watchPosition = (...a) => { post("location"); return orig(...a); };
    }
  } catch {}

  try {
    if (navigator.clipboard?.readText) {
      const orig = navigator.clipboard.readText.bind(navigator.clipboard);
      navigator.clipboard.readText = (...a) => { post("clipboard"); return orig(...a); };
    }
  } catch {}
})();
