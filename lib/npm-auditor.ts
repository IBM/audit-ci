import type { NPMAuditReportV1, NPMAuditReportV2 } from "audit-types";
import { blue } from "./colors.js";
import { reportAudit, type ReportConfig, runProgram } from "./common.js";
import {
  type AuditCiConfig,
  type AuditCiFullConfig,
  mapAuditCiConfigToAuditCiFullConfig,
} from "./config.js";
import Model, { type Summary } from "./model.js";

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

  let stdoutBuffer: any = {};
  function outListener(data: any) {
    stdoutBuffer = { ...stdoutBuffer, ...data };
  }

  const stderrBuffer: any[] = [];
  function errorListener(line: any) {
    stderrBuffer.push(line);
  }

  const cliArguments = ["audit", "--json"];
  if (registry) {
    cliArguments.push("--registry", registry);
  }
  if (skipDevelopmentDependencies) {
    cliArguments.push("--production");
  }
  if (extraArguments) {
    cliArguments.push(...extraArguments);
  }
  const options = { cwd: directory };
  await runProgram(npmExec, cliArguments, options, outListener, errorListener);
  if (stderrBuffer.length > 0) {
    throw new Error(`Invocation of npm audit failed:\n${stderrBuffer.join("\n")}`);
  }
  return stdoutBuffer;
}
export function isV2Audit(
  parsedOutput: NPMAuditReportV1.Audit | NPMAuditReportV2.Audit,
): parsedOutput is NPMAuditReportV2.Audit {
  return "auditReportVersion" in parsedOutput && parsedOutput.auditReportVersion === 2;
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
          const relevantAdvisoryLevels = Object.keys(advisories).filter((advisory) => {
            const severity = advisories[advisory].severity;
            return severity !== "info" && levels[severity];
          });

          const relevantNpmV2Advisories: Record<string, NPMAuditReportV2.Advisory> = {};
          for (const advisory of relevantAdvisoryLevels) {
            relevantNpmV2Advisories[advisory] = advisories[advisory];
          }
          return relevantNpmV2Advisories;
        } else {
          const advisories = parsedOutput.advisories;
          const advisoryKeys = Object.keys(advisories);
          const relevantAdvisoryLevels = advisoryKeys.filter((advisory) => {
            const severity = advisories[advisory].severity;
            return severity !== "info" && levels[severity];
          });

          const relevantNpmV1Advisories: Record<string, NPMAuditReportV1.Advisory> = {};
          for (const advisory of relevantAdvisoryLevels) {
            relevantNpmV1Advisories[advisory] = advisories[advisory];
          }
          return relevantNpmV1Advisories;
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
      reportType satisfies never;
      throw new Error(
        `Invalid report type: ${reportType as string}. Should be \`['important', 'full', 'summary']\`.`,
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
  const { levels, "report-type": reportType, "output-format": outputFormat } = config;
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
export async function auditWithFullConfig(config: AuditCiFullConfig, reporter = reportAudit) {
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
