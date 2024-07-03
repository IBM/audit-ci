import { existsSync, readFileSync } from "fs";
import jju from "jju";
// eslint-disable-next-line unicorn/import-style
import * as path from "path";
import { hideBin } from "yargs/helpers";
import yargs from "yargs";
import Allowlist, { type AllowlistRecord } from "./allowlist.js";
import {
  mapVulnerabilityLevelInput,
  type VulnerabilityLevels,
} from "./map-vulnerability.js";

function mapReportTypeInput(
  config: Pick<AuditCiPreprocessedConfig, "report-type">,
) {
  const { "report-type": reportType } = config;
  switch (reportType) {
    case "full":
    case "important":
    case "summary": {
      return reportType;
    }
    default: {
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }
}

function mapExtraArgumentsInput(
  config: Pick<AuditCiPreprocessedConfig, "extra-args">,
) {
  // These args will often be flags for another command, so we
  // want to have some way of escaping args that start with a -.
  // We'll look for and remove a single backslash at the start, if present.
  return config["extra-args"].map((a) => a.replace(/^\\/, ""));
}

/**
 * The output of `Yargs`'s `parse` function.
 * This is the type of the `argv` object.
 */
type AuditCiPreprocessedConfig = {
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
  p: "auto" | "npm" | "yarn" | "pnpm";
  /** Show a full audit report */
  r: boolean;
  /** Show a full audit report */
  report: boolean;
  /** Show a summary audit report */
  s: boolean;
  /** Show a summary audit report */
  summary: boolean;
  /** Package manager */
  "package-manager": "auto" | "npm" | "yarn" | "pnpm";
  a: string[];
  allowlist: AllowlistRecord[];
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
  /** extra positional args for underlying audit command */
  "extra-args": string[];
};

// Rather than exporting a weird union type, we resolve the type to a simple object.
type ComplexConfig = Omit<
  AuditCiPreprocessedConfig,
  // Remove single-letter options from the base config to avoid confusion.
  | "allowlist"
  | "a"
  | "p"
  | "o"
  | "d"
  | "s"
  | "r"
  | "l"
  | "m"
  | "h"
  | "c"
  | "low"
  | "moderate"
  | "high"
  | "critical"
> & {
  /** Package manager */
  "package-manager": "npm" | "yarn" | "pnpm";
  /** An object containing a list of modules, advisories, and module paths that should not break the build if their vulnerability is found. */
  allowlist: Allowlist;
  /** The vulnerability levels to fail on, if `moderate` is set `true`, `high` and `critical` should be as well. */
  levels: { [K in keyof VulnerabilityLevels]: VulnerabilityLevels[K] };
  /**
   * A path to npm, uses npm from `$PATH` if not specified
   * @internal
   */
  _npm?: string;
  /**
   * A path to pnpm, uses pnpm from `$PATH` if not specified
   * @internal
   */
  _pnpm?: string;
  /**
   * A path to yarn, uses yarn from `$PATH` if not specified
   * @internal
   */
  _yarn?: string;
};

export type AuditCiFullConfig = {
  [K in keyof ComplexConfig]: ComplexConfig[K];
};

type AuditCiConfigComplex = Omit<
  Partial<AuditCiFullConfig>,
  "levels" | "allowlist"
> & {
  allowlist?: AllowlistRecord[];
  low?: boolean;
  moderate?: boolean;
  high?: boolean;
  critical?: boolean;
};

export type AuditCiConfig = {
  [K in keyof AuditCiConfigComplex]: AuditCiConfigComplex[K];
};

/**
 * @param pmArgument the package manager (including the `auto` option)
 * @param directory the directory where the package manager files exist
 * @returns the non-`auto` package manager
 */
function resolvePackageManagerType(
  pmArgument: "auto" | "npm" | "yarn" | "pnpm",
  directory: string,
): "npm" | "yarn" | "pnpm" {
  switch (pmArgument) {
    case "npm":
    case "pnpm":
    case "yarn": {
      return pmArgument;
    }
    case "auto": {
      const getPath = (file: string) => path.resolve(directory, file);
      // TODO: Consider prioritizing `package.json#packageManager` for determining the package manager.
      const packageLockExists = existsSync(getPath("package-lock.json"));
      if (packageLockExists) return "npm";
      const shrinkwrapExists = existsSync(getPath("npm-shrinkwrap.json"));
      if (shrinkwrapExists) return "npm";
      const yarnLockExists = existsSync(getPath("yarn.lock"));
      if (yarnLockExists) return "yarn";
      const pnpmLockExists = existsSync(getPath("pnpm-lock.yaml"));
      if (pnpmLockExists) return "pnpm";
      throw new Error(
        "Cannot establish package-manager type, missing package-lock.json, yarn.lock, and pnpm-lock.yaml.",
      );
    }
    default: {
      throw new Error(`Unexpected package manager argument: ${pmArgument}`);
    }
  }
}

const defaults = {
  low: false,
  moderate: false,
  high: false,
  critical: false,
  "skip-dev": false,
  "pass-enoaudit": false,
  "retry-count": 5,
  "report-type": "important" as const,
  report: false,
  directory: "./",
  "package-manager": "auto" as const,
  "show-not-found": true,
  "show-found": true,
  registry: undefined,
  summary: false,
  allowlist: [] as AllowlistRecord[],
  "output-format": "text" as const,
  "extra-args": [] as string[],
};

function mapArgvToAuditCiConfig(argv: AuditCiPreprocessedConfig) {
  const allowlist = Allowlist.mapConfigToAllowlist(argv);

  const {
    low,
    moderate,
    high,
    critical,
    "package-manager": packageManager,
    directory,
  } = argv;

  const resolvedPackageManager = resolvePackageManagerType(
    packageManager,
    directory,
  );

  const result: AuditCiFullConfig = {
    ...argv,
    "package-manager": resolvedPackageManager,
    levels: mapVulnerabilityLevelInput({
      low,
      moderate,
      high,
      critical,
    }),
    "report-type": mapReportTypeInput(argv),
    allowlist: allowlist,
    "extra-args": mapExtraArgumentsInput(argv),
  };
  return result;
}

export function mapAuditCiConfigToAuditCiFullConfig(
  config: AuditCiConfig,
): AuditCiFullConfig {
  const packageManager =
    config["package-manager"] ?? defaults["package-manager"];
  const directory = config.directory ?? defaults.directory;

  const resolvedPackageManager = resolvePackageManagerType(
    packageManager,
    directory,
  );

  const allowlist = Allowlist.mapConfigToAllowlist({
    allowlist: config.allowlist ?? defaults.allowlist,
  });

  const levels = mapVulnerabilityLevelInput({
    low: config.low ?? defaults.low,
    moderate: config.moderate ?? defaults.moderate,
    high: config.high ?? defaults.high,
    critical: config.critical ?? defaults.critical,
  });

  const fullConfig: AuditCiFullConfig = {
    "skip-dev": config["skip-dev"] ?? defaults["skip-dev"],
    "pass-enoaudit": config["pass-enoaudit"] ?? defaults["pass-enoaudit"],
    "retry-count": config["retry-count"] ?? defaults["retry-count"],
    "report-type": config["report-type"] ?? defaults["report-type"],
    "package-manager": resolvedPackageManager,
    directory,
    report: config.report ?? defaults.report,
    registry: config.registry ?? defaults.registry,
    "show-not-found": config["show-not-found"] ?? defaults["show-not-found"],
    "show-found": config["show-found"] ?? defaults["show-found"],
    summary: config.summary ?? defaults.summary,
    "output-format": config["output-format"] ?? defaults["output-format"],
    allowlist,
    levels,
    "extra-args": config["extra-args"] ?? defaults["extra-args"],
  };
  return fullConfig;
}

export async function runYargs(): Promise<AuditCiFullConfig> {
  const { argv } = yargs(hideBin(process.argv))
    .config("config", (configPath) =>
      // Supports JSON, JSONC, & JSON5
      jju.parse(readFileSync(configPath, "utf8"), {
        // When passing an allowlist using NSRecord syntax, yargs will throw an error
        // "Invalid JSON config file". We need to add this flag to prevent that.
        null_prototype: false,
      }),
    )
    .options({
      l: {
        alias: "low",
        default: defaults.low,
        describe: "Exit for low vulnerabilities or higher",
        type: "boolean",
      },
      m: {
        alias: "moderate",
        default: defaults.moderate,
        describe: "Exit for moderate vulnerabilities or higher",
        type: "boolean",
      },
      h: {
        alias: "high",
        default: defaults.high,
        describe: "Exit for high vulnerabilities or higher",
        type: "boolean",
      },
      c: {
        alias: "critical",
        default: defaults.critical,
        describe: "Exit for critical vulnerabilities",
        type: "boolean",
      },
      p: {
        alias: "package-manager",
        default: defaults["package-manager"],
        describe: "Choose a package manager",
        choices: ["auto", "npm", "yarn", "pnpm"],
      },
      r: {
        alias: "report",
        default: defaults.report,
        describe: "Show a full audit report",
        type: "boolean",
      },
      s: {
        alias: "summary",
        default: defaults.summary,
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
        default: defaults["show-found"],
        describe: "Show allowlisted advisories that are found",
        type: "boolean",
      },
      "show-not-found": {
        default: defaults["show-not-found"],
        describe: "Show allowlisted advisories that are not found",
        type: "boolean",
      },
      registry: {
        default: defaults.registry,
        describe: "The registry to resolve packages by name and version",
        type: "string",
      },
      "report-type": {
        default: defaults["report-type"],
        describe: "Format for the audit report results",
        type: "string",
        choices: ["important", "summary", "full"],
      },
      "retry-count": {
        default: defaults["retry-count"],
        describe:
          "The number of attempts audit-ci calls an unavailable registry before failing",
        type: "number",
      },
      "pass-enoaudit": {
        default: defaults["pass-enoaudit"],
        describe:
          "Pass if no audit is performed due to the registry returning ENOAUDIT",
        type: "boolean",
      },
      "skip-dev": {
        default: defaults["skip-dev"],
        describe: "Skip devDependencies",
        type: "boolean",
      },
      "extra-args": {
        default: [],
        describe: "Pass additional arguments to the underlying audit command",
        type: "array",
      },
    })
    .help("help");

  // yargs doesn't support aliases + TypeScript
  const awaitedArgv = (await argv) as unknown as AuditCiPreprocessedConfig;
  const auditCiConfig = mapArgvToAuditCiConfig(awaitedArgv);
  return auditCiConfig;
}
