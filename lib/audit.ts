import { yellow } from "./colors";
import { ReportConfig } from "./common";
import type { AuditCiFullConfig } from "./config";
import type { Summary } from "./model";
import * as npmAuditer from "./npm-auditer";
import * as pnpmAuditer from "./pnpm-auditer";
import * as yarnAuditer from "./yarn-auditer";

const PARTIAL_RETRY_ERROR_MSG = {
  // The three ENOAUDIT error messages for NPM are:
  // `Either your login credentials are invalid or your registry (${opts.registry}) does not support audit.`
  // `Your configured registry (${opts.registry}) does not support audit requests.`
  // `Your configured registry (${opts.registry}) may not support audit requests, or the audit endpoint may be temporarily unavailable.`
  // Between them, all three use the phrasing 'not support audit'.
  npm: [`not support audit`],
  yarn: ["503 Service Unavailable"],
  // TODO: Identify retry-able error message for pnpm
  pnpm: [],
} as const;

function getAuditor(
  packageManager: "npm" | "yarn" | "pnpm"
): typeof yarnAuditer | typeof npmAuditer | typeof pnpmAuditer {
  switch (packageManager) {
    case "yarn":
      return yarnAuditer;
    case "npm":
      return npmAuditer;
    case "pnpm":
      return pnpmAuditer;
    default:
      throw new Error(`Invalid package manager: ${packageManager}`);
  }
}

async function audit(
  config: AuditCiFullConfig,
  reporter?: (summary: Summary, config: ReportConfig) => Summary
) {
  const {
    "pass-enoaudit": passENoAudit,
    "retry-count": maxRetryCount,
    "package-manager": packageManager,
    "output-format": outputFormat,
  } = config;
  const auditor = getAuditor(packageManager);

  async function run(attempt = 0): Promise<Summary | undefined> {
    try {
      const result = await auditor.auditWithFullConfig(config, reporter);
      return result;
    } catch (error: any) {
      const message = error.message || error;
      const isRetryableMessage =
        typeof message === "string" &&
        PARTIAL_RETRY_ERROR_MSG[packageManager].some((retryErrorMessage) =>
          message.includes(retryErrorMessage)
        );
      const shouldRetry = attempt < maxRetryCount && isRetryableMessage;
      if (shouldRetry) {
        if (outputFormat === "text") {
          console.log("Retrying audit...");
        }
        return run(attempt + 1);
      }
      const shouldPassWithoutAuditing = passENoAudit && isRetryableMessage;
      if (shouldPassWithoutAuditing) {
        console.warn(
          yellow,
          `ACTION RECOMMENDED: An audit could not performed due to ${maxRetryCount} audits that resulted in ENOAUDIT. Perform an audit manually and verify that no significant vulnerabilities exist before merging.`
        );
        return;
      }
      throw error;
    }
  }

  return await run();
}

export default audit;
