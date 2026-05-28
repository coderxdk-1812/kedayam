// Phase R4 — extended PSL coverage for PK / KE / NG / ID.
//
// Bounded curated expansion only — see extension/lib/lookalike.js PSL block.

import { describe, it, expect } from "vitest";
import { rootDomain, lookalikeAnalysis } from "../../extension/lib/lookalike.js";

describe("R4 — additional country-code eTLD+1 extraction", () => {
  const cases = [
    // .pk
    ["hbl.com.pk", "hbl.com.pk"],
    ["login.hbl.com.pk", "hbl.com.pk"],
    ["agency.gov.pk", "agency.gov.pk"],
    // .ke
    ["equitybank.co.ke", "equitybank.co.ke"],
    ["sub.equitybank.co.ke", "equitybank.co.ke"],
    ["gov.go.ke", "gov.go.ke"],
    // .ng
    ["gtbank.com.ng", "gtbank.com.ng"],
    ["secure.gtbank.com.ng", "gtbank.com.ng"],
    ["agency.gov.ng", "agency.gov.ng"],
    // .id
    ["bca.co.id", "bca.co.id"],
    ["m.bca.co.id", "bca.co.id"],
    ["agency.go.id", "agency.go.id"],
  ];
  for (const [host, expected] of cases) {
    it(`${host} → ${expected}`, () => {
      expect(rootDomain(host)).toBe(expected);
    });
  }

  it("does not regress AU/NZ/UK/JP/BR/IN/ZA extraction", () => {
    expect(rootDomain("login.commbank.com.au")).toBe("commbank.com.au");
    expect(rootDomain("sub.bank.co.nz")).toBe("bank.co.nz");
    expect(rootDomain("sub.barclays.co.uk")).toBe("barclays.co.uk");
    expect(rootDomain("sub.mizuho.co.jp")).toBe("mizuho.co.jp");
    expect(rootDomain("a.itau.com.br")).toBe("itau.com.br");
    expect(rootDomain("onlinesbi.co.in")).toBe("onlinesbi.co.in");
    expect(rootDomain("secure.fnb.co.za")).toBe("fnb.co.za");
  });

  it("lookalike scoring remains stable for trusted .com brands", () => {
    const r = lookalikeAnalysis("paypa1.com");
    expect(r.match).toBeTruthy();
  });

  it("plain .com extraction unchanged", () => {
    expect(rootDomain("a.b.paypal.com")).toBe("paypal.com");
  });
});
