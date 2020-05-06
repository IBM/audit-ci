/*
 * Copyright IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const fs = require("fs");
const path = require("path");
const yargs = require("yargs");
const audit = require("./audit");
const { printAuditCiVersion } = require("./audit-ci-version");
const { green, red } = require("./colors");

printAuditCiVersion();

const { argv } = yargs
  .config("config")
  .options({
    l: {
      alias: "low",
      default: false,
      describe: "Exit for low vulnerabilities or higher",
      type: "boolean",
    },
    m: {
      alias: "moderate",
      default: false,
      describe: "Exit for moderate vulnerabilities or higher",
      type: "boolean",
    },
    h: {
      alias: "high",
      default: false,
      describe: "Exit for high vulnerabilities or higher",
      type: "boolean",
    },
    c: {
      alias: "critical",
      default: false,
      describe: "Exit for critical vulnerabilities",
      type: "boolean",
    },
    p: {
      alias: "package-manager",
      default: "auto",
      describe: "Choose a package manager",
      choices: ["auto", "npm", "yarn"],
    },
    r: {
      alias: "report",
      default: false,
      describe: "Show a full audit report",
      type: "boolean",
    },
    s: {
      alias: "summary",
      default: false,
      describe: "Show a summary audit report",
      type: "boolean",
    },
    a: {
      alias: "advisories",
      default: [],
      describe: "Whitelisted advisory ids",
      type: "array",
    },
    w: {
      alias: "whitelist",
      default: [],
      describe: "Whitelisted module names",
      type: "array",
    },
    d: {
      alias: "directory",
      default: "./",
      describe: "The directory containing the package.json to audit",
      type: "string",
    },
    "show-not-found": {
      default: true,
      describe: "Show whitelisted advisories that are not found",
      type: "boolean",
    },
    registry: {
      default: undefined,
      describe: "The registry to resolve packages by name and version",
      type: "string",
    },
    "report-type": {
      default: "important",
      describe: "Format for the audit report results",
      type: "string",
      choices: ["important", "summary", "full"],
    },
    "retry-count": {
      default: 5,
      describe:
        "The number of attempts audit-ci calls an unavailable registry before failing",
      type: "number",
    },
    "pass-enoaudit": {
      default: false,
      describe:
        "Pass if no audit is performed due to the registry returning ENOAUDIT",
      type: "boolean",
    },
    "path-whitelist": {
      default: [],
      describe: "Whitelisted vulnerability paths",
      type: "array",
    },
  })
  .help("help");

function mapVulnerabilityLevelInput(config) {
  if (config.l) {
    return { low: true, moderate: true, high: true, critical: true };
  }
  if (config.m) {
    return { low: false, moderate: true, high: true, critical: true };
  }
  if (config.h) {
    return { low: false, moderate: false, high: true, critical: true };
  }
  if (config.c) {
    return { low: false, moderate: false, high: false, critical: true };
  }
  return { low: false, moderate: false, high: false, critical: false };
}

function mapReportTypeInput(config) {
  const { "report-type": reportType } = config;
  switch (reportType) {
    case "full":
    case "important":
    case "summary":
      return reportType;
    default:
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`
      );
  }
}

argv.levels = mapVulnerabilityLevelInput(argv);
argv["report-type"] = mapReportTypeInput(argv);

/**
 * @param {'auto' | 'npm' | 'yarn'} pmArg the package manager (including the `auto` option)
 * @param {string} directory the directory where the package manager files exist
 * @returns {'npm' | 'yarn'} the non-`auto` package manager
 */
function getPackageManagerType(pmArg, directory) {
  switch (pmArg) {
    case "npm":
    case "yarn":
      return pmArg;
    case "auto": {
      const getPath = (file) => path.resolve(directory, file);
      const packageLockExists = fs.existsSync(getPath("package-lock.json"));
      if (packageLockExists) return "npm";
      const shrinkwrapExists = fs.existsSync(getPath("npm-shrinkwrap.json"));
      if (shrinkwrapExists) return "npm";
      const yarnLockExists = fs.existsSync(getPath("yarn.lock"));
      if (yarnLockExists) return "yarn";
      throw Error(
        "Cannot establish package-manager type, missing package-lock.json and yarn.lock."
      );
    }
    default:
      throw Error(`Unexpected package manager argument: ${pmArg}`);
  }
}

const pm = getPackageManagerType(argv.p, argv.d);

(async () => {
  try {
    await audit(pm, argv);
    console.log(green, `Passed ${pm} security audit.`);
  } catch (err) {
    const message = err.message || err;
    console.error(red, message);
    console.error(red, "Exiting...");
    process.exitCode = 1;
  }
})();
