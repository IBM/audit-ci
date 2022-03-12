import { blue } from "./colors";
import { reportAudit, runProgram } from "./common";
import { AuditCiConfig } from "./config";
import Model from "./model";

async function runNpmAudit(config) {
  const { directory, registry, _npm } = config;
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
  if (config["skip-dev"]) {
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

/**
 * @param {*} parsedOutput
 * @param {*} levels
 * @param {"full" | "important" | "summary"} reportType
 * @param {"text" | "json"} outputFormat
 */
function printReport(parsedOutput, levels, reportType, outputFormat) {
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
 * @param {{directory: string, report: { full?: boolean, summary?: boolean }, allowlist: object, registry: string, levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `directory`: the directory containing the package.json to audit.
 * `report-type`: [`important`, `summary`, `full`] how the audit report is displayed.
 * `allowlist`: an object containing a list of modules, advisories, and module paths that should not break the build if their vulnerability is found.
 * `registry`: the registry to resolve packages by name and version.
 * `show-not-found`: show allowlisted advisories that are not found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * `skip-dev`: skip devDependencies, defaults to false
 * `_npm`: a path to npm, uses npm from PATH if not specified.
 * @returns {Promise<any>} Returns the audit report summary on resolve, `Error` on rejection.
 */
export async function audit(config, reporter = reportAudit) {
  const parsedOutput = await runNpmAudit(config);
  if (parsedOutput.error) {
    const { code, summary } = parsedOutput.error;
    throw new Error(`code ${code}: ${summary}`);
  }
  return report(parsedOutput, config, reporter);
}
