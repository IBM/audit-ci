import type {
  GitHubAdvisoryId,
  NPMAuditReportV1,
  NPMAuditReportV2,
} from "audit-types";
import { blue } from "./colors.js";
import { reportAudit, ReportConfig, runProgram } from "./common.js";
import {
  AuditCiConfig,
  AuditCiFullConfig,
  mapAuditCiConfigToAuditCiFullConfig,
} from "./config.js";
import Model, { Summary } from "./model.js";

async function runNpmAudit(
  config: AuditCiFullConfig,
): Promise<NPMAuditReportV1.AuditResponse | NPMAuditReportV2.AuditResponse> {
  const {
    directory,
    registry,
    _npm,
    "skip-dev": skipDevelopmentDependencies,
    "extra-args": extraArguments,
  } = config;
  const npmExec = _npm || "npm";

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stdoutBuffer: any = {};
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function outListener(data: any) {
    stdoutBuffer = { ...stdoutBuffer, ...data };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const stderrBuffer: any[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function errorListener(line: any) {
    stderrBuffer.push(line);
  }

  const arguments_ = ["audit", "--json"];
  if (registry) {
    arguments_.push("--registry", registry);
  }
  if (skipDevelopmentDependencies) {
    arguments_.push("--production");
  }
  if (extraArguments) {
    arguments_.push(...extraArguments);
  }
  const options = { cwd: directory };
  await runProgram(npmExec, arguments_, options, outListener, errorListener);
  if (stderrBuffer.length > 0) {
    throw new Error(
      `Invocation of npm audit failed:\n${stderrBuffer.join("\n")}`,
    );
  }
  return stdoutBuffer;
}
export function isV2Audit(
  parsedOutput: NPMAuditReportV1.Audit | NPMAuditReportV2.Audit,
): parsedOutput is NPMAuditReportV2.Audit {
  return (
    "auditReportVersion" in parsedOutput &&
    parsedOutput.auditReportVersion === 2
  );
}

function printReport(
  parsedOutput: NPMAuditReportV1.Audit | NPMAuditReportV2.Audit,
  levels: AuditCiFullConfig["levels"],
  reportType: "full" | "important" | "summary",
  outputFormat: "text" | "json",
) {
  const printReportObject = (text: string, object: unknown) => {
    if (outputFormat === "text") {
      console.log(blue, text);
    }
    console.log(JSON.stringify(object, undefined, 2));
  };
  switch (reportType) {
    case "full": {
      printReportObject("NPM audit report JSON:", parsedOutput);
      break;
    }
    case "important": {
      const relevantAdvisories = (() => {
        if (isV2Audit(parsedOutput)) {
          const advisories = parsedOutput.vulnerabilities;
          const relevantAdvisoryLevels = Object.keys(advisories).filter(
            (advisory) => {
              const severity = advisories[advisory].severity;
              return severity !== "info" && levels[severity];
            },
          );

          const relevantAdvisories: Record<string, NPMAuditReportV2.Advisory> =
            {};
          for (const advisory of relevantAdvisoryLevels) {
            relevantAdvisories[advisory] = advisories[advisory];
          }
          return relevantAdvisories;
        } else {
          const advisories = parsedOutput.advisories;
          const advisoryKeys = Object.keys(advisories) as GitHubAdvisoryId[];
          const relevantAdvisoryLevels = advisoryKeys.filter((advisory) => {
            const severity = advisories[advisory].severity;
            return severity !== "info" && levels[severity];
          });

          const relevantAdvisories: Record<
            GitHubAdvisoryId,
            NPMAuditReportV1.Advisory
          > = {};
          for (const advisory of relevantAdvisoryLevels) {
            relevantAdvisories[advisory] = advisories[advisory];
          }
          return relevantAdvisories;
        }
      })();

      const keyFindings = {
        advisories: relevantAdvisories,
        metadata: parsedOutput.metadata,
      };
      printReportObject("NPM audit report results:", keyFindings);
      break;
    }
    case "summary": {
      printReportObject("NPM audit report summary:", parsedOutput.metadata);
      break;
    }
    default: {
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }
}

export function report(
  parsedOutput: NPMAuditReportV1.Audit | NPMAuditReportV2.Audit,
  config: AuditCiFullConfig,
  reporter: (
    summary: Summary,
    config: ReportConfig,
    audit: NPMAuditReportV1.Audit | NPMAuditReportV2.Audit,
  ) => Summary,
) {
  const {
    levels,
    "report-type": reportType,
    "output-format": outputFormat,
  } = config;
  printReport(parsedOutput, levels, reportType, outputFormat);
  const model = new Model(config);
  const summary = model.load(parsedOutput);
  return reporter(summary, config, parsedOutput);
}

/**
 * Audit your NPM project!
 *
 * @returns Returns the audit report summary on resolve, `Error` on rejection.
 */
export async function auditWithFullConfig(
  config: AuditCiFullConfig,
  reporter = reportAudit,
) {
  const parsedOutput = await runNpmAudit(config);
  if ("error" in parsedOutput) {
    const { code, summary } = parsedOutput.error;
    throw new Error(`code ${code}: ${summary}`);
  } else if ("message" in parsedOutput) {
    throw new Error(parsedOutput.message);
  }
  return report(parsedOutput, config, reporter);
}

/**
 * Audit your NPM project!
 *
 * @returns Returns the audit report summary on resolve, `Error` on rejection.
 */
export async function audit(config: AuditCiConfig, reporter = reportAudit) {
  const fullConfig = mapAuditCiConfigToAuditCiFullConfig(config);
  return await auditWithFullConfig(fullConfig, reporter);
}
