const { bugs, version: auditCiVersion } = require("../package.json");
const { yellow } = require("./colors");

if (!auditCiVersion) {
  console.log(
    yellow,
    `Could not identify audit-ci version. Please report this issue to ${bugs}.`
  );
}

/**
 * @param {"text" | "json" | undefined} outputFormat the output format
 */
function printAuditCiVersion(outputFormat) {
  if (outputFormat === "text") {
    console.log(`audit-ci version: ${auditCiVersion}`);
  }
}

module.exports = { auditCiVersion, printAuditCiVersion };
