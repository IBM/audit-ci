const { version: auditCiVersion } = require("../package.json");
const { yellow } = require("./colors");

if (!auditCiVersion) {
  console.log(
    yellow,
    "Could not identify audit-ci version. Please report this issue to https://github.com/IBM/audit-ci/issues."
  );
}

module.exports = { auditCiVersion };
