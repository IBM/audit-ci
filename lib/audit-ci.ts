import audit from "./audit";
import { printAuditCiVersion } from "./audit-ci-version";
import { green, red } from "./colors";
import { runYargs } from "./config";

export async function runAuditCi() {
  const auditCiConfig = await runYargs();

  const { "package-manager": packageManager, "output-format": outputFormat } =
    auditCiConfig;

  printAuditCiVersion(outputFormat);

  try {
    await audit(auditCiConfig);
    if (outputFormat === "text") {
      console.log(green, `Passed ${packageManager} security audit.`);
    }
  } catch (error: any) {
    if (outputFormat === "text") {
      const message = error.message || error;
      console.error(red, message);
      console.error(red, "Exiting...");
    }
    process.exitCode = 1;
  }
}
