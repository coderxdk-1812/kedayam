import { describe, it, expect } from "vitest";
import { AuthFlowGraph, sharedAuthFlowGraph, resetSharedAuthFlowGraph } from "../../extension/lib/authFlowGraph.js";

describe("authFlowGraph", () => {
  it("refuses to store secret-shaped values", () => {
    const g = new AuthFlowGraph();
    expect(() => g.record("credential", { origin: "https://a.example", password: "x" })).toThrow();
    expect(() => g.record("mfa", { origin: "https://a.example", otp: "123" })).toThrow();
    expect(() => g.record("token", { origin: "https://a.example", token: "t" })).toThrow();
  });

  it("flags credential-relay when POST origin was never visited", () => {
    const g = new AuthFlowGraph();
    g.record("entry", { origin: "https://login.corp.example" });
    g.record("credential", { origin: "https://login.corp.example",
      postOrigin: "https://harvester.cc" });
    const a = g.anomalies();
    expect(a.some((x) => x.id === "credential-relay")).toBe(true);
  });

  it("flags oauth-token-drift across origins", () => {
    const g = new AuthFlowGraph();
    g.record("entry", { origin: "https://app.example" });
    g.record("oauth", { origin: "https://idp.example" });
    g.record("token", { origin: "https://relay.attacker.cc" });
    expect(g.anomalies().some((a) => a.id === "oauth-token-drift")).toBe(true);
  });

  it("flags iframe-origin-swap", () => {
    const g = new AuthFlowGraph();
    g.record("entry", { origin: "https://parent.example" });
    g.record("credential", { origin: "https://embedded.attacker.cc",
      inIframe: true, postOrigin: "https://embedded.attacker.cc" });
    expect(g.anomalies().some((a) => a.id === "iframe-origin-swap")).toBe(true);
  });

  it("flags mfa-origin-split", () => {
    const g = new AuthFlowGraph();
    g.record("entry", { origin: "https://login.example" });
    g.record("credential", { origin: "https://login.example",
      postOrigin: "https://login.example" });
    g.record("mfa", { origin: "https://mfa-relay.cc",
      postOrigin: "https://mfa-relay.cc" });
    expect(g.anomalies().some((a) => a.id === "mfa-origin-split")).toBe(true);
  });

  it("flags redirect-storm at 4+ unrelated origins", () => {
    const g = new AuthFlowGraph();
    g.record("entry", { origin: "https://a.example" });
    g.record("redirect", { origin: "https://b.example" });
    g.record("redirect", { origin: "https://c.example" });
    g.record("redirect", { origin: "https://d.example" });
    g.record("redirect", { origin: "https://e.example" });
    expect(g.anomalies().some((a) => a.id === "redirect-storm")).toBe(true);
  });

  it("serialize() never includes secrets and is JSON-safe", () => {
    const g = new AuthFlowGraph();
    g.record("entry", { origin: "https://a.example" });
    g.record("credential", { origin: "https://a.example", postOrigin: "https://b.example" });
    const s = g.serialize();
    const j = JSON.stringify(s);
    expect(j).not.toMatch(/password|otp|token/i);
    expect(s.steps.length).toBe(2);
  });

  it("expires steps past TTL", () => {
    let t = 1000;
    const g = new AuthFlowGraph({ now: () => t });
    g.record("entry", { origin: "https://a.example" });
    t += 10 * 60 * 1000;
    g.record("credential", { origin: "https://a.example" });
    expect(g.steps().length).toBe(1);
  });

  it("shared graph is a singleton and resettable", () => {
    resetSharedAuthFlowGraph();
    const a = sharedAuthFlowGraph();
    const b = sharedAuthFlowGraph();
    expect(a).toBe(b);
    resetSharedAuthFlowGraph();
    expect(sharedAuthFlowGraph()).not.toBe(a);
  });
});
