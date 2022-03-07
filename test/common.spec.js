const { expect } = require("chai");
const { matchString } = require("../lib/common");

describe("matchString", () => {
  it("works for various prefixes and suffixes of wildcards", () => {
    expect(matchString("*|axios", "GHSA-42xw-2xvc-qx8m|axios")).to.eql(true);
    expect(matchString("12|axios>*", "12|axios>124")).to.eql(true);
    expect(matchString("*|axios>123", "12|axios>123")).to.eql(true);
    expect(matchString("*|axios>*", "12|axios>123")).to.eql(true);
  });
});
