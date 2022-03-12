import { AuditCiConfig } from "./config";
// Ignoring importing package.json because that changes the package's build
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { bugs, version } = require("../package.json");
import { yellow } from "./colors";

export const auditCiVersion = version as string;

if (!auditCiVersion) {
  console.log(
    yellow,
    `Could not identify audit-ci version. Please report this issue to ${bugs}.`
  );
}

export function printAuditCiVersion(
  outputFormat?: AuditCiConfig["output-format"]
) {
  if (outputFormat === "text") {
    console.log(`audit-ci version: ${auditCiVersion}`);
  }
}
