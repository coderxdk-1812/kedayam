// Phase R3 — international PSL / eTLD+1 correctness.

import { describe, it, expect } from "vitest";
import { rootDomain, lookalikeAnalysis } from "../../extension/lib/lookalike.js";

describe("R3 — country-code secondary domain extraction", () => {
  const cases = [
    // .nz
    ["bank.co.nz", "bank.co.nz"],
    ["sub.bank.co.nz", "bank.co.nz"],
    ["www.bank.co.nz", "www.bank.co.nz"], // www strip happens upstream
    // .au
    ["commbank.com.au", "commbank.com.au"],
    ["foo.commbank.com.au", "commbank.com.au"],
    ["agency.gov.au", "agency.gov.au"],
    // .za
    ["fnb.co.za", "fnb.co.za"],
    ["x.fnb.co.za", "fnb.co.za"],
    // .uk
    ["barclays.co.uk", "barclays.co.uk"],
    ["sub.barclays.co.uk", "barclays.co.uk"],
    // .jp
    ["mizuho.co.jp", "mizuho.co.jp"],
    ["sub.mizuho.co.jp", "mizuho.co.jp"],
    // .br
    ["itau.com.br", "itau.com.br"],
    // .in
    ["sbi.co.in", "sbi.co.in"],
    ["onlinesbi.co.in", "onlinesbi.co.in"],
    // plain .com still works
    ["paypal.com", "paypal.com"],
    ["a.b.paypal.com", "paypal.com"],
  ];
  for (const [host, expected] of cases) {
    it(`${host} → ${expected}`, () => {
      expect(rootDomain(host)).toBe(expected);
    });
  }

  it("does not regress existing trusted-root calibration for .com lookalikes", () => {
    const r = lookalikeAnalysis("paypa1.com");
    expect(r.match).toBeTruthy();
  });

  it("regional banking domains are extracted as full eTLD+1", () => {
    expect(rootDomain("login.commbank.com.au")).toBe("commbank.com.au");
    expect(rootDomain("secure.fnb.co.za")).toBe("fnb.co.za");
    expect(rootDomain("netbanking.hdfcbank.com")).toBe("hdfcbank.com");
  });

  it("handles empty/invalid input gracefully", () => {
    expect(rootDomain("")).toBe("");
    expect(rootDomain(null)).toBe(null);
    expect(rootDomain(undefined)).toBe(undefined);
  });
});
