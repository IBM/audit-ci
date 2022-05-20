// @ts-check
const { expect } = require("chai");
const semver = require("semver");
const sinon = require("sinon");
const {
  auditCiVersion,
  printAuditCiVersion,
} = require("../dist/audit-ci-version");

describe("audit-ci package", () => {
  it("gets the version of the audit-ci package", () => {
    const packageVersion = auditCiVersion;
    semver.valid(packageVersion);
    semver.gte(packageVersion, "2.4.2");
  });
  it("prints audit-ci version", () => {
    const stub = sinon.stub(console, "log");
    printAuditCiVersion("text");
    expect(stub.calledOnceWithExactly(`audit-ci version: ${auditCiVersion}`));
    // @ts-expect-error restoring console.log
    console.log.restore();
  });
  it("does not print audit-ci version with JSON reporting", () => {
    const stub = sinon.stub(console, "log");
    printAuditCiVersion("json");
    expect(stub.notCalled);
    // @ts-expect-error restoring console.log
    console.log.restore();
  });
});
