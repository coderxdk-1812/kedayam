// Kedayam — pure Chrome→Firefox manifest transform.
//
// Kept as a pure function so the cross-browser build stays reproducible and the
// transform is unit-testable without a browser. Single source of truth is the
// Chrome manifest; this derives the Gecko variant from it so the two never drift.
//
// Firefox MV3 differences handled here:
//   * requires browser_specific_settings.gecko.id
//   * Firefox has no background *service worker* yet — it uses an event-page
//     background script (ESM via "type":"module")
//   * Chrome-only keys (minimum_chrome_version) are dropped
//   * web_accessible_resources: use_dynamic_url is a Chrome-ism; dropped
//
// NOTE: the produced manifest is structurally valid but still needs a real
// Firefox runtime pass (web-ext lint / load) before store submission — see
// STATUS.md "Known gaps".

/**
 * @param {object} chrome  parsed Chrome manifest.json
 * @param {object} [opts]  { geckoId?: string, minVersion?: string }
 * @returns {object} Firefox-adapted manifest
 */
export function toFirefoxManifest(chrome, opts = {}) {
  const geckoId = opts.geckoId || "kedayam@cyberchandu.com";
  const minVersion = opts.minVersion || "121.0";
  const m = structuredClone(chrome);

  // 1. Gecko identity.
  m.browser_specific_settings = { gecko: { id: geckoId, strict_min_version: minVersion } };

  // 2. Background: service_worker → event-page script (ESM).
  if (m.background && m.background.service_worker) {
    m.background = { scripts: [m.background.service_worker], type: "module" };
  }

  // 3. Drop Chrome-only keys.
  delete m.minimum_chrome_version;

  // 4. web_accessible_resources: strip the Chrome-only use_dynamic_url flag.
  if (Array.isArray(m.web_accessible_resources)) {
    m.web_accessible_resources = m.web_accessible_resources.map((war) => {
      if (war && typeof war === "object") {
        const { use_dynamic_url, ...rest } = war;
        void use_dynamic_url;
        return rest;
      }
      return war;
    });
  }

  return m;
}
