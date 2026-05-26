// Red team — JS-level tampering. Phishing kits may try to monkey-patch
// querySelector, freeze our observers, or poison prototypes. Our DOM-reading
// helpers (safeDom) rely on captured native references — these tests assert
// that captured references survive hostile mutation.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { JSDOM } from "jsdom";

describe("red team — JS tampering", () => {
  let dom, safeDom;
  beforeEach(async () => {
    dom = new JSDOM("<!doctype html><body><form id=f><input type=password></form></body>");
    global.window = dom.window;
    global.document = dom.window.document;
    global.Document = dom.window.Document;
    global.Element = dom.window.Element;
    global.Node = dom.window.Node;
    global.HTMLElement = dom.window.HTMLElement;
    global.HTMLInputElement = dom.window.HTMLInputElement;
    global.EventTarget = dom.window.EventTarget;
    vi.resetModules();
    safeDom = await import("../../extension/lib/safeDom.js?red=1");
  });

  it("captured native reference table is frozen", () => {
    expect(Object.isFrozen(safeDom._native)).toBe(true);
  });

  it("qs() continues to work after page overwrites querySelector", () => {
    Document.prototype.querySelector = function () { throw new Error("blocked"); };
    Element.prototype.querySelector = function () { throw new Error("blocked"); };
    const form = safeDom.qs(document, "form#f");
    expect(form).not.toBeNull();
  });

  it("prototype poisoning does not affect arbitration purity", async () => {
    // @ts-expect-error intentional pollution
    Object.prototype.__kedayam_poisoned = true;
    vi.resetModules();
    const { arbitrate } = await import("../../extension/lib/arbitration.js?red=1");
    const out = arbitrate({
      allowlistRoot: false, isReputableRoot: false, isTrustedProvider: false,
      hasAuthWorkflow: false,
      lookalike: { match: null, confidence: 0 },
      idnSpoof: false,
      clone: { confidence: 0 },
      phishing: { credentialHarvest: false, externalFormPost: false,
        brandImpersonation: null, confidence: 0, authRisk: "none" },
    });
    expect(out).toBeDefined();
    expect(Array.isArray(out.rules)).toBe(true);
    // @ts-expect-error cleanup
    delete Object.prototype.__kedayam_poisoned;
  });

  it("listener-scope dispose() removes all attached listeners", () => {
    const scope = safeDom.createListenerScope();
    const target = document.createElement("div");
    let fired = 0;
    scope.on(target, "click", () => fired++);
    target.dispatchEvent(new dom.window.Event("click"));
    expect(fired).toBe(1);
    scope.dispose();
    target.dispatchEvent(new dom.window.Event("click"));
    expect(fired).toBe(1);
    expect(scope.size()).toBe(0);
  });
});
