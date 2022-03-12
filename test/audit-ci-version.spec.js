const semver = require("semver");
const { auditCiVersion } = require("../dist/audit-ci-version");

describe("audit-ci package", () => {
  it("gets the version of the audit-ci package", () => {
    const packageVersion = auditCiVersion;
    semver.valid(packageVersion);
    semver.gte(packageVersion, "2.4.2");
  });
});
