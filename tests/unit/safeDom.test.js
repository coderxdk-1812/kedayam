import { describe, it, expect, beforeEach } from "vitest";
import { JSDOM } from "jsdom";

describe("safeDom — frozen native references", () => {
  let dom;
  beforeEach(() => {
    dom = new JSDOM("<!doctype html><body><form id=f><input type=password></form></body>");
    // Install globals BEFORE importing safeDom so it captures these prototypes.
    global.window = dom.window;
    global.document = dom.window.document;
    global.Document = dom.window.Document;
    global.Element = dom.window.Element;
    global.Node = dom.window.Node;
    global.HTMLElement = dom.window.HTMLElement;
    global.HTMLInputElement = dom.window.HTMLInputElement;
    global.EventTarget = dom.window.EventTarget;
  });

  it("qs/qsa work even after page monkey-patches Document.prototype", async () => {
    const safe = await import("../../extension/lib/safeDom.js?v=1");
    // Page poisons querySelector to return null for password fields.
    Document.prototype.querySelector = function () {
      return null;
    };
    Element.prototype.querySelector = function () {
      return null;
    };
    const form = safe.qs(document, "form#f");
    expect(form).not.toBeNull();
    const pwd = safe.qs(form, "input[type=password]");
    expect(pwd).not.toBeNull();
  });

  it("getAttribute survives prototype tampering", async () => {
    const safe = await import("../../extension/lib/safeDom.js?v=2");
    const form = document.querySelector("form");
    form.setAttribute("action", "/login");
    Element.prototype.getAttribute = function () {
      return "https://evil.example/x";
    };
    expect(safe.attr(form, "action")).toBe("/login");
  });

  it("listener scope disposes everything cleanly", async () => {
    const safe = await import("../../extension/lib/safeDom.js?v=3");
    const scope = safe.createListenerScope();
    let calls = 0;
    const h = () => calls++;
    scope.on(document, "click", h);
    document.dispatchEvent(new dom.window.Event("click"));
    expect(calls).toBe(1);
    scope.dispose();
    document.dispatchEvent(new dom.window.Event("click"));
    expect(calls).toBe(1);
    expect(scope.size()).toBe(0);
  });
});
