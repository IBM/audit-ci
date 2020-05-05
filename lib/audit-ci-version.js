const { version: auditCiVersion } = require("../package.json");

if (!auditCiVersion) {
  console.log(
    "\x1b[33m%s\x1b[0m",
    "Could not identify audit-ci version. Please report this issue to https://github.com/IBM/audit-ci/issues."
  );
}

module.exports = { auditCiVersion };
