const { expect } = require("chai");
const {
  matchString,
  gitHubAdvisoryUrlToAdvisoryId,
} = require("../dist/common");

describe("matchString", () => {
  it("works for various prefixes and suffixes of wildcards", () => {
    expect(matchString("*|axios", "GHSA-42xw-2xvc-qx8m|axios")).to.eql(true);
    expect(matchString("12|axios>*", "12|axios>124")).to.eql(true);
    expect(matchString("*|axios>123", "12|axios>123")).to.eql(true);
    expect(matchString("*|axios>*", "12|axios>123")).to.eql(true);
  });
});

describe("gitHubAdvisoryUrlToAdvisoryId", () => {
  it("converts github-advisory-url to just the advisory-id", () => {
    expect(
      gitHubAdvisoryUrlToAdvisoryId(
        "https://github.com/advisories/GHSA-qrpm-p2h7-hrv2"
      )
    ).to.eql("GHSA-qrpm-p2h7-hrv2");
    expect(
      gitHubAdvisoryUrlToAdvisoryId("https://github.com/advisories/GHSA-1")
    ).to.eql("GHSA-1");
  });
});
