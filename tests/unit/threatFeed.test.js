import { describe, it, expect } from "vitest";
import {
  normalizeFeedHost,
  parseFeed,
  matchBlocklist,
  refreshThreatFeed,
  loadStoredBlocklist,
  FREE_FEEDS,
} from "../../extension/lib/threatFeed.js";
import { BLOCKLIST_SEED } from "../../extension/lib/rules/blocklistSeed.js";

describe("normalizeFeedHost", () => {
  it("passes a bare host", () => expect(normalizeFeedHost("evil.tld")).toBe("evil.tld"));
  it("strips hosts-file IP prefix", () =>
    expect(normalizeFeedHost("0.0.0.0 bad.example")).toBe("bad.example"));
  it("extracts host from a URL", () =>
    expect(normalizeFeedHost("https://phish.tld/login?x=1")).toBe("phish.tld"));
  it("drops www and trailing dot", () => expect(normalizeFeedHost("www.bad.tld.")).toBe("bad.tld"));
  it("skips comments and blanks", () => {
    expect(normalizeFeedHost("# comment")).toBe("");
    expect(normalizeFeedHost("   ")).toBe("");
  });
  it("rejects non-hosts", () => expect(normalizeFeedHost("not a host")).toBe(""));
});

describe("parseFeed", () => {
  it("builds a deduped set from mixed lines", () => {
    const set = parseFeed("# header\n0.0.0.0 a.tld\nhttps://b.tld/x\nb.tld\n\n");
    expect(set.has("a.tld")).toBe(true);
    expect(set.has("b.tld")).toBe(true);
    expect(set.size).toBe(2);
  });
});

describe("matchBlocklist", () => {
  it("matches a bundled seed host exactly", () => {
    const seed = BLOCKLIST_SEED[0];
    const r = matchBlocklist(seed);
    expect(r.match).toBe(true);
    expect(r.source).toBe("bundled");
  });
  it("matches a subdomain via eTLD+1 against a feed entry", () => {
    const r = matchBlocklist("login.evil-kit.tk", new Set(["evil-kit.tk"]));
    expect(r.match).toBe(true);
    expect(r.source).toBe("feed");
  });
  it("does not match a clean host", () => {
    expect(matchBlocklist("github.com").match).toBe(false);
  });
  it("is safe on bad input", () => {
    expect(matchBlocklist(null).match).toBe(false);
    expect(matchBlocklist("").match).toBe(false);
  });
});

describe("refreshThreatFeed (opt-in, injected deps)", () => {
  it("fetches, parses, and stores feed entries; skips dead mirrors", async () => {
    const store = {};
    const fakeFetch = async (url) => {
      if (url === FREE_FEEDS[0].url) return { ok: true, text: async () => "bad1.tld\nbad2.tld\n" };
      if (url === FREE_FEEDS[1].url) throw new Error("network down");
      return { ok: true, text: async () => "https://bad3.tld/x\n" };
    };
    const count = await refreshThreatFeed(
      fakeFetch,
      (obj) => {
        Object.assign(store, obj);
      },
      { now: 123 },
    );
    expect(count).toBeGreaterThanOrEqual(3);
    const loaded = await loadStoredBlocklist(async (k) => ({ [k]: store[k] }));
    expect(loaded.has("bad1.tld")).toBe(true);
    expect(loaded.has("bad3.tld")).toBe(true);
  });
});
