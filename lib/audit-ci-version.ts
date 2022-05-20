import type { AuditCiConfig } from "./config";
// Ignoring importing package.json because that changes the package's build
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version } = require("../package.json");

export const auditCiVersion = version as string;

export function printAuditCiVersion(
  outputFormat?: AuditCiConfig["output-format"]
) {
  if (outputFormat === "text") {
    console.log(`audit-ci version: ${auditCiVersion}`);
  }
}
