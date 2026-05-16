import { describe, expect, it } from "vitest";
import {
  deduplicate,
  gitHubAdvisoryIdToUrl,
  gitHubAdvisoryUrlToAdvisoryId,
  isGitHubAdvisoryId,
  matchString,
} from "../lib/common.js";
import { getErrorMessages } from "./common.js";

describe("matchString", () => {
  it("works for various prefixes and suffixes of wildcards", () => {
    expect(matchString("*|axios", "GHSA-42xw-2xvc-qx8m|axios")).toBe(true);
    expect(matchString("12|axios>*", "12|axios>124")).toBe(true);
    expect(matchString("*|axios>123", "12|axios>123")).toBe(true);
    expect(matchString("*|axios>*", "12|axios>123")).toBe(true);
  });
});

describe("gitHubAdvisoryUrlToAdvisoryId", () => {
  it("converts github-advisory-url to just the advisory-id", () => {
    expect(
      gitHubAdvisoryUrlToAdvisoryId("https://github.com/advisories/GHSA-qrpm-p2h7-hrv2"),
    ).toEqual("GHSA-qrpm-p2h7-hrv2");
    expect(gitHubAdvisoryUrlToAdvisoryId("https://github.com/advisories/GHSA-1")).toEqual("GHSA-1");
  });
});

describe("gitHubAdvisoryIdToUrl", () => {
  it("converts a GitHub advisory identifier to the GitHub URL for the advisory", () => {
    const id = "GHSA-qrpm-p2h7-hrv2";
    expect(gitHubAdvisoryIdToUrl(id)).toEqual(`https://github.com/advisories/${id}`);
  });
  it("does not handle null or undefined in a special way", () => {
    // @ts-expect-error testing null
    // oxlint-disable-next-line unicorn/no-null
    expect(gitHubAdvisoryIdToUrl(null)).toEqual(`https://github.com/advisories/null`);
    // @ts-expect-error testing undefined
    // oxlint-disable-next-line unicorn/no-useless-undefined
    expect(gitHubAdvisoryIdToUrl(undefined)).toEqual(`https://github.com/advisories/undefined`);
  });
});

describe("deduplicate", () => {
  it("removes duplicates from an array", () => {
    expect(deduplicate(["1", "2", "2", "1", "2", "3", "1"])).toEqual(["1", "2", "3"]);
  });
});

describe("getErrorMessages", () => {
  it("returns a string for non-error values", () => {
    expect(getErrorMessages("plain failure")).toBe("plain failure");
  });

  it("includes nested error causes", () => {
    const error = new Error("request failed");
    error.cause = new Error("ECONNREFUSED");
    expect(getErrorMessages(error)).toContain("ECONNREFUSED");
    expect(getErrorMessages(error)).toContain("request failed");
  });
});

describe("isGitHubAdvisoryId", () => {
  it("returns true for valid GitHub advisory IDs", () => {
    expect(isGitHubAdvisoryId("GHSA-qrpm-p2h7-hrv2")).toBe(true);
    expect(isGitHubAdvisoryId("GHSA-random")).toBe(true); // lazy implementation
    expect(isGitHubAdvisoryId("GHSA")).toBe(true); // lazy implementation
  });
  it("returns false for invalid GitHub advisory IDs", () => {
    expect(isGitHubAdvisoryId("qrpm-p2h7-hrv2")).toBe(false);
    // oxlint-disable-next-line unicorn/no-useless-undefined
    expect(isGitHubAdvisoryId(undefined)).toBe(false);
    // oxlint-disable-next-line unicorn/no-null
    expect(isGitHubAdvisoryId(null)).toBe(false);
  });
});
