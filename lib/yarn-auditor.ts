import type { YarnAudit, Yarn2And3AuditReport } from "audit-types";
import { blue, red, yellow } from "./colors.js";
import { type ReportConfig, reportAudit, runProgram } from "./common.js";
import {
  mapAuditCiConfigToAuditCiFullConfig,
  type AuditCiConfig,
  type AuditCiFullConfig,
} from "./config.js";
import Model, { type Summary } from "./model.js";
import {
  MINIMUM_YARN_BERRY_VERSION,
  MINIMUM_YARN_CLASSIC_VERSION,
  getYarnVersion,
  yarnAuditSupportsRegistry,
  yarnSupportsAudit,
  yarnSupportsClassicAudit,
} from "./yarn-version.js";

const printJson = (data: unknown) => {
  console.log(JSON.stringify(data, undefined, 2));
};

const isClassicAuditAdvisory = (
  data: unknown,
  type: unknown,
): data is YarnAudit.AuditAdvisoryResponse => {
  return type === "auditAdvisory";
};

const isClassicAuditSummary = (data: unknown, type: unknown): data is YarnAudit.AuditSummary => {
  return type === "auditSummary";
};

function printYarnHeader(
  yarnName: string,
  reportType: AuditCiFullConfig["report-type"],
  outputFormat: AuditCiFullConfig["output-format"],
) {
  if (outputFormat !== "text") {
    return;
  }
  switch (reportType) {
    case "full": {
      console.log(blue, `${yarnName} audit report JSON:`);
      break;
    }
    case "important": {
      console.log(blue, `${yarnName} audit report results:`);
      break;
    }
    case "summary": {
      console.log(blue, `${yarnName} audit report summary:`);
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

function createClassicPrintAuditData(
  levels: AuditCiFullConfig["levels"],
  reportType: AuditCiFullConfig["report-type"],
): (line: YarnAudit.AuditResponse) => void {
  switch (reportType) {
    case "full": {
      return (line) => {
        printJson(line);
      };
    }
    case "important": {
      return ({ type, data }) => {
        if (isClassicAuditAdvisory(data, type)) {
          const severity = data.advisory.severity;
          if (severity !== "info" && levels[severity]) {
            printJson(data);
          }
        } else if (isClassicAuditSummary(data, type)) {
          printJson(data);
        }
      };
    }
    case "summary": {
      return ({ type, data }) => {
        if (isClassicAuditAdvisory(data, type)) {
          printJson(data);
        }
      };
    }
    default: {
      reportType satisfies never;
      throw new Error(
        `Invalid report type: ${reportType as string}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }
}

function createBerryPrintAuditData(
  reportType: AuditCiFullConfig["report-type"],
): (line: Yarn2And3AuditReport.AuditResponse) => void {
  switch (reportType) {
    case "full": {
      return (line) => {
        printJson(line);
      };
    }
    case "important":
    case "summary": {
      return (line: Yarn2And3AuditReport.AuditResponse) => {
        if ("metadata" in line) {
          printJson(line.metadata);
        }
      };
    }
    default: {
      reportType satisfies never;
      throw new Error(
        `Invalid report type: ${reportType as string}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }
}

function processClassicAuditLine(
  line: YarnAudit.AuditResponse,
  model: Model,
  printAuditData: (line: YarnAudit.AuditResponse) => void,
): boolean {
  const { type, data } = line;
  printAuditData(line);

  if (type === "info" && data === "No lockfile found.") {
    return true;
  }

  if (type !== "auditAdvisory") {
    return false;
  }

  model.process(data.advisory);
  return false;
}

function processBerryAuditOutput(
  line: Yarn2And3AuditReport.AuditResponse,
  model: Model,
  printAuditData: (line: Yarn2And3AuditReport.AuditResponse) => void,
) {
  printAuditData(line);

  if ("advisories" in line) {
    for (const advisory of Object.values<Yarn2And3AuditReport.Advisory>(line.advisories)) {
      model.process(advisory);
    }
  }
}

export function reportClassic(
  lines: readonly YarnAudit.AuditResponse[],
  config: AuditCiFullConfig,
  reporter: (summary: Summary, config: ReportConfig) => Summary = reportAudit,
): Summary {
  const { levels, "report-type": reportType, "output-format": outputFormat } = config;
  printYarnHeader("Yarn", reportType, outputFormat);
  const printAuditData = createClassicPrintAuditData(levels, reportType);
  const model = new Model(config);
  let missingLockFile = false;

  for (const line of lines) {
    if (processClassicAuditLine(line, model, printAuditData)) {
      missingLockFile = true;
    }
  }

  if (missingLockFile) {
    console.warn(
      yellow,
      "No yarn.lock file. This does not affect auditing, but it may be a mistake.",
    );
  }

  const summary = model.getSummary((a) => a.github_advisory_id);
  return reporter(summary, config);
}

export function reportBerry(
  parsedOutput: Yarn2And3AuditReport.AuditResponse,
  config: AuditCiFullConfig,
  reporter: (summary: Summary, config: ReportConfig) => Summary = reportAudit,
): Summary {
  const { "report-type": reportType, "output-format": outputFormat } = config;
  printYarnHeader("Yarn Berry", reportType, outputFormat);
  const printAuditData = createBerryPrintAuditData(reportType);
  const model = new Model(config);
  processBerryAuditOutput(parsedOutput, model, printAuditData);
  const summary = model.getSummary((a) => a.github_advisory_id);
  return reporter(summary, config);
}

/**
 * Audit your Yarn project!
 *
 * @returns Returns the audit report summary on resolve, `Error` on rejection.
 */
export async function auditWithFullConfig(
  config: AuditCiFullConfig,
  reporter = reportAudit,
): Promise<Summary> {
  const {
    levels,
    registry,
    "report-type": reportType,
    "skip-dev": skipDevelopmentDependencies,
    "output-format": outputFormat,
    _yarn,
    directory,
    "extra-args": extraArguments,
  } = config;
  const yarnExec = _yarn || "yarn";
  let missingLockFile = false;
  const model = new Model(config);

  const yarnVersion = getYarnVersion(yarnExec, directory);
  const isYarnVersionSupported = yarnSupportsAudit(yarnVersion);
  if (!isYarnVersionSupported) {
    throw new Error(
      `Yarn ${yarnVersion} not supported, must be ^${MINIMUM_YARN_CLASSIC_VERSION} or >=${MINIMUM_YARN_BERRY_VERSION}`,
    );
  }
  const isYarnClassic = yarnSupportsClassicAudit(yarnVersion);
  const yarnName = isYarnClassic ? `Yarn` : `Yarn Berry`;
  printYarnHeader(yarnName, reportType, outputFormat);
  const printClassicAuditData = createClassicPrintAuditData(levels, reportType);
  const printBerryAuditData = createBerryPrintAuditData(reportType);

  function outListener(line: YarnAudit.AuditResponse | Yarn2And3AuditReport.AuditResponse) {
    try {
      if (isYarnClassic) {
        if (
          processClassicAuditLine(line as YarnAudit.AuditResponse, model, printClassicAuditData)
        ) {
          missingLockFile = true;
        }
      } else {
        processBerryAuditOutput(
          line as Yarn2And3AuditReport.AuditResponse,
          model,
          printBerryAuditData,
        );
      }
    } catch (error) {
      console.error(red, `ERROR: Cannot JSONStream.parse response:`);
      console.error(line);
      throw error;
    }
  }

  // oxlint-disable-next-line @typescript-eslint/no-explicit-any
  const stderrBuffer: any[] = [];
  // oxlint-disable-next-line @typescript-eslint/no-explicit-any
  function errorListener(line: any) {
    stderrBuffer.push(line);

    if (line.type === "error") {
      throw new Error(line.data);
    }
  }
  const options = { cwd: directory };
  const arguments_ = isYarnClassic
    ? ["audit", "--json", ...(skipDevelopmentDependencies ? ["--groups", "dependencies"] : [])]
    : [
        "npm",
        "audit",
        "--recursive",
        "--json",
        "--all",
        ...(skipDevelopmentDependencies ? ["--environment", "production"] : []),
      ];
  if (registry) {
    const auditRegistrySupported = yarnAuditSupportsRegistry(yarnVersion);
    if (auditRegistrySupported) {
      arguments_.push("--registry", registry);
    } else {
      console.warn(yellow, "Yarn audit does not support the registry flag yet.");
    }
  }
  if (extraArguments) {
    arguments_.push(...extraArguments);
  }
  await runProgram(yarnExec, arguments_, options, outListener, errorListener);
  if (missingLockFile) {
    console.warn(
      yellow,
      "No yarn.lock file. This does not affect auditing, but it may be a mistake.",
    );
  }

  const summary = model.getSummary((a) => a.github_advisory_id);
  return reporter(summary, config);
}

/**
 * Run audit-ci with Yarn Classic or Yarn Berry.
 */
export async function audit(config: AuditCiConfig, reporter = reportAudit) {
  const fullConfig = mapAuditCiConfigToAuditCiFullConfig(config);
  return await auditWithFullConfig(fullConfig, reporter);
}
