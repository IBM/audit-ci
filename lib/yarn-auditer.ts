import * as childProcess from "child_process";
import * as semver from "semver";
import { blue, red, yellow } from "./colors";
import { reportAudit, runProgram } from "./common";
import { AuditCiConfig } from "./config";
import Model from "./model";

const MINIMUM_YARN_CLASSIC_VERSION = "1.12.3";
const MINIMUM_YARN_BERRY_VERSION = "2.4.0";
/**
 * Change this to the appropriate version when
 * yarn audit --registry is supported:
 * @see https://github.com/yarnpkg/yarn/issues/7012
 */
const MINIMUM_YARN_AUDIT_REGISTRY_VERSION = "99.99.99";

function getYarnVersion(cwd?: string | URL) {
  const version = childProcess
    .execSync("yarn -v", { cwd })
    .toString()
    .replace("\n", "");
  return version;
}

function yarnSupportsClassicAudit(yarnVersion: string | semver.SemVer) {
  return semver.satisfies(yarnVersion, `^${MINIMUM_YARN_CLASSIC_VERSION}`);
}

function yarnSupportsBerryAudit(yarnVersion: string | semver.SemVer) {
  return semver.gte(yarnVersion, MINIMUM_YARN_BERRY_VERSION);
}

function yarnSupportsAudit(yarnVersion: string | semver.SemVer) {
  return (
    yarnSupportsClassicAudit(yarnVersion) || yarnSupportsBerryAudit(yarnVersion)
  );
}

function yarnAuditSupportsRegistry(yarnVersion: string | semver.SemVer) {
  return semver.gte(yarnVersion, MINIMUM_YARN_AUDIT_REGISTRY_VERSION);
}

const printJson = (data: unknown) => {
  console.log(JSON.stringify(data, undefined, 2));
};

/**
 * Audit your Yarn project!
 *
 * @returns Returns the audit report summary on resolve, `Error` on rejection.
 */
export async function audit(
  config: AuditCiConfig,
  reporter = reportAudit
): Promise<any> {
  const {
    levels,
    registry,
    "report-type": reportType,
    "skip-dev": skipDevelopmentDependencies,
    o: outputFormat,
    _yarn,
    directory,
  } = config;
  const yarnExec = _yarn || "yarn";
  let missingLockFile = false;
  const model = new Model(config);

  const yarnVersion = getYarnVersion(directory);
  const isYarnVersionSupported = yarnSupportsAudit(yarnVersion);
  if (!isYarnVersionSupported) {
    throw new Error(
      `Yarn ${yarnVersion} not supported, must be ^${MINIMUM_YARN_CLASSIC_VERSION} or >=${MINIMUM_YARN_BERRY_VERSION}`
    );
  }
  const isYarnClassic = yarnSupportsClassicAudit(yarnVersion);
  const yarnName = isYarnClassic ? `Yarn` : `Yarn Berry`;

  const printHeader = (text: string) => {
    if (outputFormat === "text") {
      console.log(blue, text);
    }
  };
  switch (reportType) {
    case "full":
      printHeader(`${yarnName} audit report JSON:`);
      break;
    case "important":
      printHeader(`${yarnName} audit report results:`);
      break;
    case "summary":
      printHeader(`${yarnName} audit report summary:`);
      break;
    default:
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`
      );
  }

  // Define a function to print based on the report type.
  let printAuditData;
  switch (reportType) {
    case "full":
      printAuditData = (line: unknown) => {
        printJson(line);
      };
      break;
    case "important":
      printAuditData = isYarnClassic
        ? ({ type, data }) => {
            if (
              (type === "auditAdvisory" && levels[data.advisory.severity]) ||
              type === "auditSummary"
            ) {
              printJson(data);
            }
          }
        : ({ metadata }) => {
            printJson(metadata);
          };
      break;
    case "summary":
      printAuditData = isYarnClassic
        ? ({ type, data }: { type: string; data: any }) => {
            if (type === "auditSummary") {
              printJson(data);
            }
          }
        : ({ metadata }: { metadata: any }) => {
            printJson(metadata);
          };
      break;
    default:
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`
      );
  }

  function outListener(line) {
    try {
      if (isYarnClassic) {
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

        for (const advisory of Object.values(line.advisories)) {
          model.process(advisory);
        }
      }
    } catch (error) {
      console.error(red, `ERROR: Cannot JSONStream.parse response:`);
      console.error(line);
      throw error;
    }
  }

  const stderrBuffer: any[] = [];
  function errorListener(line) {
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
        ...(skipDevelopmentDependencies
          ? ["--environment", "production"]
          : ["--all"]),
      ];
  if (registry) {
    const auditRegistrySupported = yarnAuditSupportsRegistry(yarnVersion);
    if (auditRegistrySupported) {
      arguments_.push("--registry", registry);
    } else {
      console.warn(
        yellow,
        "Yarn audit does not support the registry flag yet."
      );
    }
  }
  await runProgram(yarnExec, arguments_, options, outListener, errorListener);
  if (missingLockFile) {
    console.warn(
      yellow,
      "No yarn.lock file. This does not affect auditing, but it may be a mistake."
    );
  }

  const summary = model.getSummary((a) => a.github_advisory_id);
  return reporter(summary, config);
}
