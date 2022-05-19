// @ts-check
const { expect } = require("chai");
const { default: Allowlist } = require("../dist/allowlist");

describe("Allowlist", () => {
  it("can map config to empty Allowlist", () => {
    const { advisories, modules, paths } = Allowlist.mapConfigToAllowlist({
      allowlist: [],
    });
    expect(advisories).to.deep.equal([]);
    expect(modules).to.deep.equal([]);
    expect(paths).to.deep.equal([]);
  });
  it("can map config to modules Allowlist", () => {
    const { advisories, modules, paths } = Allowlist.mapConfigToAllowlist({
      allowlist: ["axios", "mocha"],
    });
    expect(advisories).to.deep.equal([]);
    expect(modules).to.deep.equal(["axios", "mocha"]);
    expect(paths).to.deep.equal([]);
  });
  it("can map config to advisories Allowlist", () => {
    const { advisories, modules, paths } = Allowlist.mapConfigToAllowlist({
      allowlist: [
        "GHSA-pw2r-vq6v-hr8c",
        "GHSA-74fj-2j2h-c42q",
        "GHSA-cph5-m8f7-6c5x",
        "GHSA-4w2v-q235-vp99",
        "GHSA-42xw-2xvc-qx8m",
      ],
    });
    expect(advisories).to.deep.equal([
      "GHSA-pw2r-vq6v-hr8c",
      "GHSA-74fj-2j2h-c42q",
      "GHSA-cph5-m8f7-6c5x",
      "GHSA-4w2v-q235-vp99",
      "GHSA-42xw-2xvc-qx8m",
    ]);
    expect(modules).to.deep.equal([]);
    expect(paths).to.deep.equal([]);
  });

  it("can map config to paths Allowlist", () => {
    const { advisories, modules, paths } = Allowlist.mapConfigToAllowlist({
      allowlist: [
        "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
        "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
        "GHSA-cph5-m8f7-6c5x|axios",
        "GHSA-4w2v-q235-vp99|axios",
        "GHSA-42xw-2xvc-qx8m|axios",
      ],
    });
    expect(advisories).to.deep.equal([]);
    expect(modules).to.deep.equal([]);
    expect(paths).to.deep.equal([
      "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
      "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
      "GHSA-cph5-m8f7-6c5x|axios",
      "GHSA-4w2v-q235-vp99|axios",
      "GHSA-42xw-2xvc-qx8m|axios",
    ]);
  });

  it("can remove duplicates", () => {
    const { advisories, modules, paths } = Allowlist.mapConfigToAllowlist({
      allowlist: [
        "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
        "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
      ],
    });
    expect(advisories).to.deep.equal([]);
    expect(modules).to.deep.equal([]);
    expect(paths).to.deep.equal(["GHSA-74fj-2j2h-c42q|axios>follow-redirects"]);
  });
});
