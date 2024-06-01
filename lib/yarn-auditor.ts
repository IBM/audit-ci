import type { YarnAudit, Yarn2And3AuditReport } from "audit-types";
import { blue, red, yellow } from "./colors.js";
import { reportAudit, runProgram } from "./common.js";
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

const isClassicAuditSummary = (
  data: unknown,
  type: unknown,
): data is YarnAudit.AuditSummary => {
  return type === "auditSummary";
};

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

  function isClassicGuard(
    response: YarnAudit.AuditResponse | Yarn2And3AuditReport.AuditResponse,
  ): response is YarnAudit.AuditResponse {
    return isYarnClassic;
  }

  const printHeader = (text: string) => {
    if (outputFormat === "text") {
      console.log(blue, text);
    }
  };
  switch (reportType) {
    case "full": {
      printHeader(`${yarnName} audit report JSON:`);
      break;
    }
    case "important": {
      printHeader(`${yarnName} audit report results:`);
      break;
    }
    case "summary": {
      printHeader(`${yarnName} audit report summary:`);
      break;
    }
    default: {
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }

  // Define a function to print based on the report type.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let printAuditData: any;
  switch (reportType) {
    case "full": {
      printAuditData = (line: unknown) => {
        printJson(line);
      };
      break;
    }
    case "important": {
      printAuditData = isYarnClassic
        ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ({ type, data }: any) => {
            if (isClassicAuditAdvisory(data, type)) {
              const severity = data.advisory.severity;
              if (severity !== "info" && levels[severity]) {
                printJson(data);
              }
            } else if (isClassicAuditSummary(data, type)) {
              printJson(data);
            }
          }
        : ({ metadata }: { metadata: Yarn2And3AuditReport.AuditMetadata }) => {
            printJson(metadata);
          };
      break;
    }
    case "summary": {
      printAuditData = isYarnClassic
        ? ({ type, data }: { type: unknown; data: unknown }) => {
            if (isClassicAuditAdvisory(data, type)) {
              printJson(data);
            }
          }
        : ({ metadata }: { metadata: Yarn2And3AuditReport.AuditMetadata }) => {
            printJson(metadata);
          };
      break;
    }
    default: {
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }

  function outListener(
    line: YarnAudit.AuditResponse | Yarn2And3AuditReport.AuditResponse,
  ) {
    try {
      if (isClassicGuard(line)) {
        const { type, data } = line;
        printAuditData(line);

        if (type === "info" && data === "No lockfile found.") {
          missingLockFile = true;
          return;
        }

        if (type !== "auditAdvisory") {
          return;
        }

        model.process(data.advisory);
      } else {
        printAuditData(line);

        if ("advisories" in line) {
          for (const advisory of Object.values<Yarn2And3AuditReport.Advisory>(
            line.advisories,
          )) {
            model.process(advisory);
          }
        }
      }
    } catch (error) {
      console.error(red, `ERROR: Cannot JSONStream.parse response:`);
      console.error(line);
      throw error;
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const stderrBuffer: any[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function errorListener(line: any) {
    stderrBuffer.push(line);

    if (line.type === "error") {
      throw new Error(line.data);
    }
  }
  const options = { cwd: directory };
  const arguments_ = isYarnClassic
    ? [
        "audit",
        "--json",
        ...(skipDevelopmentDependencies ? ["--groups", "dependencies"] : []),
      ]
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
      console.warn(
        yellow,
        "Yarn audit does not support the registry flag yet.",
      );
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
