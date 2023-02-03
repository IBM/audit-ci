import audit from "./audit";
import { green, red } from "./colors";
import { runYargs } from "./config";

/**
 * Runs the audit-ci CLI.
 */
export async function runAuditCi() {
  const auditCiConfig = await runYargs();

  const { "package-manager": packageManager, "output-format": outputFormat } =
    auditCiConfig;

  try {
    await audit(auditCiConfig);
    if (outputFormat === "text") {
      console.log(green, `Passed ${packageManager} security audit.`);
    }
  } catch (error: unknown) {
    if (outputFormat === "text") {
      const message = error instanceof Error ? error.message : error;
      console.error(red, message);
      console.error(red, "Exiting...");
    }
    process.exitCode = 1;
  }
}
