import { blue } from "./colors";
import { reportAudit, runProgram } from "./common";
import { AuditCiConfig } from "./config";
import Model from "./model";

async function runNpmAudit(config: AuditCiConfig) {
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
      printReportObject("NPM audit report JSON:", parsedOutput);
      break;
    case "important": {
      const advisories =
        parsedOutput.auditReportVersion === 2
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
  printReport(parsedOutput, config.levels, config["report-type"], config.o);
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
  if (parsedOutput.error) {
    const { code, summary } = parsedOutput.error;
    throw new Error(`code ${code}: ${summary}`);
  }
  return report(parsedOutput, config, reporter);
}
