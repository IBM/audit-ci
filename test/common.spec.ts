import { describe, expect, it } from "vitest";
import {
  deduplicate,
  gitHubAdvisoryIdToUrl,
  gitHubAdvisoryUrlToAdvisoryId,
  isGitHubAdvisoryId,
  matchString,
} from "../lib/common.js";

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
        "https://github.com/advisories/GHSA-qrpm-p2h7-hrv2",
      ),
    ).to.eql("GHSA-qrpm-p2h7-hrv2");
    expect(
      gitHubAdvisoryUrlToAdvisoryId("https://github.com/advisories/GHSA-1"),
    ).to.eql("GHSA-1");
  });
});

describe("gitHubAdvisoryIdToUrl", () => {
  it("converts a GitHub advisory identifier to the GitHub URL for the advisory", () => {
    const id = "GHSA-qrpm-p2h7-hrv2";
    expect(gitHubAdvisoryIdToUrl(id)).to.eql(
      `https://github.com/advisories/${id}`,
    );
  });
  it("does not handle null or undefined in a special way", () => {
    // @ts-expect-error testing null
    // eslint-disable-next-line unicorn/no-null
    expect(gitHubAdvisoryIdToUrl(null)).to.eql(
      `https://github.com/advisories/null`,
    );
    // @ts-expect-error testing undefined
    // eslint-disable-next-line unicorn/no-useless-undefined
    expect(gitHubAdvisoryIdToUrl(undefined)).to.eql(
      `https://github.com/advisories/undefined`,
    );
  });
});

describe("deduplicate", () => {
  it("removes duplicates from an array", () => {
    expect(deduplicate(["1", "2", "2", "1", "2", "3", "1"])).to.deep.equal([
      "1",
      "2",
      "3",
    ]);
  });
});

describe("isGitHubAdvisoryId", () => {
  it("returns true for valid GitHub advisory IDs", () => {
    expect(isGitHubAdvisoryId("GHSA-qrpm-p2h7-hrv2")).to.be.true;
    expect(isGitHubAdvisoryId("GHSA-random")).to.be.true; // lazy implementation
    expect(isGitHubAdvisoryId("GHSA")).to.be.true; // lazy implementation
  });
  it("returns false for invalid GitHub advisory IDs", () => {
    expect(isGitHubAdvisoryId("qrpm-p2h7-hrv2")).to.be.false;
    // eslint-disable-next-line unicorn/no-useless-undefined
    expect(isGitHubAdvisoryId(undefined)).to.be.false;
    // eslint-disable-next-line unicorn/no-null
    expect(isGitHubAdvisoryId(null)).to.be.false;
  });
});
