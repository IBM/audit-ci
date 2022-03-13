import { existsSync, readFileSync } from "fs";
import { parse } from "jju";
// eslint-disable-next-line unicorn/import-style
import * as path from "path";
import { config } from "yargs";
import Allowlist from "./allowlist";
import {
  mapVulnerabilityLevelInput,
  VulnerabilityLevels,
} from "./map-vulnerability";

function mapReportTypeInput(
  config: Pick<AuditCiPreprocessedConfig, "report-type">
) {
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

export type AuditCiPreprocessedConfig = {
  /** Exit for low or above vulnerabilities */
  l: boolean;
  /** Exit for moderate or above vulnerabilities */
  m: boolean;
  /** Exit for high or above vulnerabilities */
  h: boolean;
  /** Exit for critical or above vulnerabilities */
  c: boolean;
  /** Exit for low or above vulnerabilities */
  low: boolean;
  /** Exit for moderate or above vulnerabilities */
  moderate: boolean;
  /** Exit for high or above vulnerabilities */
  high: boolean;
  /** Exit for critical vulnerabilities */
  critical: boolean;
  /** Package manager */
  p: "auto" | "npm" | "yarn";
  /** Show a full audit report */
  r: boolean;
  /** Show a full audit report */
  report: boolean;
  /** Show a summary audit report */
  s: boolean;
  /** Show a summary audit report */
  summary: boolean;
  /** Package manager */
  "package-manager": "auto" | "npm" | "yarn";
  a: string[];
  allowlist: string[];
  /** The directory containing the package.json to audit */
  d: string;
  /** The directory containing the package.json to audit */
  directory: string;
  /** show allowlisted advisories that are not found. */
  "show-not-found": boolean;
  /** Show allowlisted advisories that are found */
  "show-found": boolean;
  /** the registry to resolve packages by name and version */
  registry?: string;
  /** The format of the output of audit-ci */
  o: "text" | "json";
  /** The format of the output of audit-ci */
  "output-format": "text" | "json";
  /** how the audit report is displayed. */
  "report-type": "full" | "important" | "summary";
  /** The number of attempts audit-ci calls an unavailable registry before failing */
  "retry-count": number;
  /** Pass if no audit is performed due to the registry returning ENOAUDIT */
  "pass-enoaudit": boolean;
  /** skip devDependencies */
  "skip-dev": boolean;
};

// Rather than exporting a weird union type, we resolve the type to a simple object.
type ComplexConfig = Omit<AuditCiPreprocessedConfig, "allowlist" | "a"> & {
  /** Package manager */
  p: "npm" | "yarn";
  /** Package manager */
  "package-manager": "npm" | "yarn";
  /** An object containing a list of modules, advisories, and module paths that should not break the build if their vulnerability is found. */
  allowlist: Allowlist;
  /** An object containing a list of modules, advisories, and module paths that should not break the build if their vulnerability is found. */
  a: Allowlist;
  /** The vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well. */
  levels: { [K in keyof VulnerabilityLevels]: VulnerabilityLevels[K] };
  /** A path to yarn, uses yarn from PATH if not specified (internal use only) */
  _yarn?: string;
};
export type AuditCiConfig = { [K in keyof ComplexConfig]: ComplexConfig[K] };

/**
 * @param pmArgument the package manager (including the `auto` option)
 * @param directory the directory where the package manager files exist
 * @returns the non-`auto` package manager
 */
function getPackageManagerType(
  pmArgument: "auto" | "npm" | "yarn",
  directory: string
): "npm" | "yarn" {
  switch (pmArgument) {
    case "npm":
    case "yarn":
      return pmArgument;
    case "auto": {
      const getPath = (file) => path.resolve(directory, file);
      const packageLockExists = existsSync(getPath("package-lock.json"));
      if (packageLockExists) return "npm";
      const shrinkwrapExists = existsSync(getPath("npm-shrinkwrap.json"));
      if (shrinkwrapExists) return "npm";
      const yarnLockExists = existsSync(getPath("yarn.lock"));
      if (yarnLockExists) return "yarn";
      throw new Error(
        "Cannot establish package-manager type, missing package-lock.json and yarn.lock."
      );
    }
    default:
      throw new Error(`Unexpected package manager argument: ${pmArgument}`);
  }
}

export async function runYargs(): Promise<AuditCiConfig> {
  const { argv } = config("config", (configPath) =>
    // Supports JSON, JSONC, & JSON5
    parse(readFileSync(configPath, "utf8"))
  )
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
        alias: "allowlist",
        default: [],
        describe:
          "Allowlist module names (example), advisories (123), and module paths (123|example1>example2)",
        type: "array",
      },
      d: {
        alias: "directory",
        default: "./",
        describe: "The directory containing the package.json to audit",
        type: "string",
      },
      o: {
        alias: "output-format",
        default: "text",
        describe: "The format of the output of audit-ci",
        choices: ["text", "json"],
      },
      "show-found": {
        default: true,
        describe: "Show allowlisted advisories that are found",
        type: "boolean",
      },
      "show-not-found": {
        default: true,
        describe: "Show allowlisted advisories that are not found",
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
      "skip-dev": {
        default: false,
        describe: "Skip devDependencies",
        type: "boolean",
      },
    })
    .help("help");

  // yargs doesn't support aliases + TypeScript
  const awaitedArgv = (await argv) as unknown as AuditCiPreprocessedConfig;
  const allowlist = Allowlist.mapConfigToAllowlist(awaitedArgv);

  const { l, m, h, c, p, d } = awaitedArgv;

  const packageManager = getPackageManagerType(p, d);

  const result: AuditCiConfig = {
    ...awaitedArgv,
    p: packageManager,
    "package-manager": packageManager,
    levels: mapVulnerabilityLevelInput({
      l,
      m,
      h,
      c,
    }),
    "report-type": mapReportTypeInput(awaitedArgv),
    a: allowlist,
    allowlist: allowlist,
  };
  return result;
}
