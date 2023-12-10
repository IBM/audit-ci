import { describe, expect, it } from "vitest";
import {
  default as Allowlist,
  normalizeAllowlistRecord,
  dedupeAllowlistRecords,
} from "../lib/allowlist.js";

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
        "GHSA-42xw-2xvc-qx8m",
        "GHSA-4w2v-q235-vp99",
        "GHSA-74fj-2j2h-c42q",
        "GHSA-cph5-m8f7-6c5x",
        "GHSA-pw2r-vq6v-hr8c",
      ],
    });
    expect(advisories).to.deep.equal([
      "GHSA-42xw-2xvc-qx8m",
      "GHSA-4w2v-q235-vp99",
      "GHSA-74fj-2j2h-c42q",
      "GHSA-cph5-m8f7-6c5x",
      "GHSA-pw2r-vq6v-hr8c",
    ]);
    expect(modules).to.deep.equal([]);
    expect(paths).to.deep.equal([]);
  });

  it("can map config to paths Allowlist", () => {
    const { advisories, modules, paths } = Allowlist.mapConfigToAllowlist({
      allowlist: [
        "GHSA-42xw-2xvc-qx8m|axios",
        "GHSA-4w2v-q235-vp99|axios",
        "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
        "GHSA-cph5-m8f7-6c5x|axios",
        "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
      ],
    });
    expect(advisories).to.deep.equal([]);
    expect(modules).to.deep.equal([]);
    expect(paths).to.deep.equal([
      "GHSA-42xw-2xvc-qx8m|axios",
      "GHSA-4w2v-q235-vp99|axios",
      "GHSA-74fj-2j2h-c42q|axios>follow-redirects",
      "GHSA-cph5-m8f7-6c5x|axios",
      "GHSA-pw2r-vq6v-hr8c|axios>follow-redirects",
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

describe("normalizeAllowlistRecord", () => {
  it("should normalize a string allowlist id into a NSPRecord", () => {
    const record = normalizeAllowlistRecord("myid");
    expect(record).to.eql({
      myid: {
        active: true,
        expiry: undefined,
        notes: undefined,
      },
    });
  });

  it("should normalize NSPRecord by making no modifications", () => {
    const record = normalizeAllowlistRecord({
      myid: {
        active: true,
        expiry: undefined,
        notes: undefined,
      },
    });
    expect(record).to.eql({
      myid: {
        active: true,
        expiry: undefined,
        notes: undefined,
      },
    });
  });
});

describe("dedupeAllowlistRecords", () => {
  it("should dedupe string allowlist ids", () => {
    const records = dedupeAllowlistRecords(["abc", "abc", "xyz"]);
    expect(records.length).to.eql(2);
  });

  it("should dedupe NSPRecord objects", () => {
    const records = dedupeAllowlistRecords([
      {
        abc: {
          active: true,
        },
      },
      {
        abc: {
          active: true,
        },
      },
      {
        xyz: {
          active: true,
        },
      },
    ]);

    expect(records.length).to.eql(2);
  });

  it("should dedupe mixed NSPRecord objects and string allowlist ids", () => {
    const records = dedupeAllowlistRecords([
      {
        abc: {
          active: true,
        },
      },
      "abc",
      {
        xyz: {
          active: true,
        },
      },
    ]);

    expect(records.length).to.eql(2);
  });

  it("should keep the first duped entry when deduping", () => {
    const records = dedupeAllowlistRecords([
      {
        abc: {
          active: true,
          notes: "I AM FIRST",
        },
      },
      {
        abc: {
          active: true,
          notes: "I AM SECOND",
        },
      },
    ]);

    expect(records).to.eql([
      {
        abc: {
          active: true,
          notes: "I AM FIRST",
        },
      },
    ]);
  });

  it("should keep the first duped entry when deduping mixed string ids and objects", () => {
    const records = dedupeAllowlistRecords([
      "abc",
      {
        abc: {
          active: true,
          notes: "I AM SECOND",
        },
      },
    ]);

    expect(records).to.eql([
      {
        abc: {
          active: true,
          notes: undefined,
          expiry: undefined,
        },
      },
    ]);
  });
});
