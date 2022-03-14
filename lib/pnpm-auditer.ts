import { blue, yellow } from "./colors";
import { reportAudit, runProgram } from "./common";
import { AuditCiConfig } from "./config";
import Model from "./model";

async function runPnpmAudit(config: AuditCiConfig) {
  const {
    directory,
    registry,
    _pnpm,
    "skip-dev": skipDevelopmentDependencies,
  } = config;
  const pnpmExec = _pnpm || "pnpm";

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
    console.warn(yellow, "Yarn audit does not support the registry flag yet.");
  }
  if (skipDevelopmentDependencies) {
    arguments_.push("--prod");
  }
  const options = { cwd: directory };
  await runProgram(pnpmExec, arguments_, options, outListener, errorListener);
  if (stderrBuffer.length > 0) {
    throw new Error(
      `Invocation of pnpm audit failed:\n${stderrBuffer.join("\n")}`
    );
  }
  return stdoutBuffer;
}

function printReport(
  parsedOutput: any,
  levels: any,
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
      printReportObject("PNPM audit report JSON:", parsedOutput);
      break;
    case "important": {
      const { advisories, metadata } = parsedOutput;

      const relevantAdvisoryLevels = Object.keys(advisories).filter(
        (advisory) => levels[advisories[advisory].severity]
      );

      const relevantAdvisories = {};
      for (const advisory of relevantAdvisoryLevels) {
        relevantAdvisories[advisory] = advisories[advisory];
      }

      const keyFindings = {
        advisories: relevantAdvisories,
        metadata: metadata,
      };
      printReportObject("PNPM audit report results:", keyFindings);
      break;
    }
    case "summary":
      printReportObject("PNPM audit report summary:", parsedOutput.metadata);
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
 * Audit your PNPM project!
 *
 * @returns Returns the audit report summary on resolve, `Error` on rejection.
 */
export async function audit(config: AuditCiConfig, reporter = reportAudit) {
  const parsedOutput = await runPnpmAudit(config);
  if (parsedOutput.error) {
    const { code, summary } = parsedOutput.error;
    throw new Error(`code ${code}: ${summary}`);
  }
  return report(parsedOutput, config, reporter);
}
