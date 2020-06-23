/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const childProcess = require("child_process");
const semver = require("semver");
const { blue, red, yellow } = require("./colors");
const { reportAudit, runProgram } = require("./common");
const Model = require("./Model");

const MINIMUM_YARN_VERSION = "1.12.3";
/**
 * Change this to the appropriate version when
 * yarn audit --registry is supported:
 * @see https://github.com/yarnpkg/yarn/issues/7012
 */
const MINIMUM_YARN_AUDIT_REGISTRY_VERSION = "99.99.99";

function getYarnVersion() {
  const version = childProcess.execSync("yarn -v").toString().replace("\n", "");
  return version;
}

function yarnSupportsAudit(yarnVersion) {
  return semver.gte(yarnVersion, MINIMUM_YARN_VERSION);
}

function yarnAuditSupportsRegistry(yarnVersion) {
  return semver.gte(yarnVersion, MINIMUM_YARN_AUDIT_REGISTRY_VERSION);
}

/**
 * Audit your Yarn project!
 *
 * @param {{directory: string, report: { full?: boolean, summary?: boolean }, allowlist: object, registry: string, levels: { low: boolean, moderate: boolean, high: boolean, critical: boolean }}} config
 * `directory`: the directory containing the package.json to audit.
 * `report-type`: [`important`, `summary`, `full`] how the audit report is displayed.
 * `allowlist`: an object containing a list of modules, advisories, and module paths that should not break the build if their vulnerability is found.
 * `registry`: the registry to resolve packages by name and version.
 * `show-not-found`: show allowlisted advisories that are not found.
 * `levels`: the vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well.
 * `_yarn`: a path to yarn, uses yarn from PATH if not specified.
 * @returns {Promise<any>} Returns the audit report summary on resolve, `Error` on rejection.
 */
async function audit(config, reporter = reportAudit) {
  const { levels, registry, "report-type": reportType, _yarn } = config;
  const yarnExec = _yarn || "yarn";
  let missingLockFile = false;
  const model = new Model(config);

  const yarnVersion = getYarnVersion();
  const isYarnVersionSupported = yarnSupportsAudit(yarnVersion);
  if (!isYarnVersionSupported) {
    throw new Error(
      `Yarn ${yarnVersion} not supported, must be >=${MINIMUM_YARN_VERSION}`
    );
  }

  switch (reportType) {
    case "full":
      console.log(blue, "Yarn audit report JSON:");
      break;
    case "important":
      console.log(blue, "Yarn audit report results:");
      break;
    case "summary":
      console.log(blue, "Yarn audit report summary:");
      break;
    default:
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`
      );
  }

  const printJson = (data) => {
    console.log(JSON.stringify(data, null, 2));
  };
  // Define a function to print based on the report type.
  let printAuditData;
  switch (reportType) {
    case "full":
      printAuditData = (line) => {
        printJson(line);
      };
      break;
    case "important":
      printAuditData = ({ type, data }) => {
        if (
          (type === "auditAdvisory" && levels[data.advisory.severity]) ||
          type === "auditSummary"
        ) {
          printJson(data);
        }
      };
      break;
    case "summary":
      printAuditData = ({ type, data }) => {
        if (type === "auditSummary") {
          printJson(data);
        }
      };
      break;
    default:
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`
      );
  }

  function outListener(line) {
    try {
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
    } catch (err) {
      console.error(red, `ERROR: Cannot JSONStream.parse response:`);
      console.error(line);
      throw err;
    }
  }

  const stderrBuffer = [];
  function errListener(line) {
    stderrBuffer.push(line);

    if (line.type === "error") {
      throw new Error(line.data);
    }
  }
  const options = { cwd: config.directory };
  const args = ["audit", "--json"];
  if (registry) {
    const auditRegistrySupported = yarnAuditSupportsRegistry(yarnVersion);
    if (auditRegistrySupported) {
      args.push("--registry", registry);
    } else {
      console.warn(
        yellow,
        "Yarn audit does not support the registry flag yet."
      );
    }
  }
  await runProgram(yarnExec, args, options, outListener, errListener);
  if (missingLockFile) {
    console.warn(
      yellow,
      "No yarn.lock file. This does not affect auditing, but it may be a mistake."
    );
  }

  const summary = model.getSummary((a) => a.id);
  return reporter(summary, config);
}

module.exports = { audit };
