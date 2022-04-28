import type { NPMAuditReportV1, NPMAuditReportV2 } from "audit-types";
import { blue } from "./colors";
import { reportAudit, runProgram } from "./common";
import { AuditCiConfig } from "./config";
import Model from "./model";

async function runNpmAudit(
  config: AuditCiConfig
): Promise<NPMAuditReportV1.AuditResponse | NPMAuditReportV2.AuditResponse> {
  const {
    directory,
    registry,
    _npm,
    "skip-dev": skipDevelopmentDependencies,
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

  const arguments_ = ["audit", "--json"];
  if (registry) {
    arguments_.push("--registry", registry);
  }
  if (skipDevelopmentDependencies) {
    arguments_.push("--production");
  }
  const options = { cwd: directory };
  await runProgram(npmExec, arguments_, options, outListener, errorListener);
  if (stderrBuffer.length > 0) {
    throw new Error(
      `Invocation of npm audit failed:\n${stderrBuffer.join("\n")}`
    );
  }
  return stdoutBuffer;
}
export function isV2Audit(
  parsedOutput: NPMAuditReportV1.Audit | NPMAuditReportV2.Audit
): parsedOutput is NPMAuditReportV2.Audit {
  return (
    "auditReportVersion" in parsedOutput &&
    parsedOutput.auditReportVersion === 2
  );
}

function printReport(
  parsedOutput: NPMAuditReportV1.Audit | NPMAuditReportV2.Audit,
  levels: AuditCiConfig["levels"],
  reportType: "full" | "important" | "summary",
  outputFormat: "text" | "json"
) {
  const printReportObject = (text, object) => {
    if (outputFormat === "text") {
      console.log(blue, text);
    }
    console.log(JSON.stringify(object, undefined, 2));
  };
  switch (reportType) {
    case "full":
      printReportObject("NPM audit report JSON:", parsedOutput);
      break;
    case "important": {
      const advisories = isV2Audit(parsedOutput)
        ? parsedOutput.vulnerabilities
        : parsedOutput.advisories;

      const relevantAdvisoryLevels = Object.keys(advisories).filter(
        (advisory) => levels[advisories[advisory].severity]
      );

      const relevantAdvisories = {};
      for (const advisory of relevantAdvisoryLevels) {
        relevantAdvisories[advisory] = advisories[advisory];
      }

      const keyFindings = {
        advisories: relevantAdvisories,
        metadata: parsedOutput.metadata,
      };
      printReportObject("NPM audit report results:", keyFindings);
      break;
    }
    case "summary":
      printReportObject("NPM audit report summary:", parsedOutput.metadata);
      break;
    default:
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`
      );
  }
}

export function report(parsedOutput, config: AuditCiConfig, reporter) {
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
export async function audit(config: AuditCiConfig, reporter = reportAudit) {
  const parsedOutput = await runNpmAudit(config);
  if ("error" in parsedOutput) {
    const { code, summary } = parsedOutput.error;
    throw new Error(`code ${code}: ${summary}`);
  }
  return report(parsedOutput, config, reporter);
}
