import type { Severity, YarnAudit, Yarn2And3AuditReport } from "audit-types";
import { blue, red, yellow } from "./colors.js";
import {
  gitHubAdvisoryUrlToAdvisoryId,
  reportAudit,
  runProgram,
} from "./common.js";
import {
  mapAuditCiConfigToAuditCiFullConfig,
  type AuditCiConfig,
  type AuditCiFullConfig,
} from "./config.js";
import Model, { type ProcessedAdvisory, type Summary } from "./model.js";
import {
  MINIMUM_YARN_BERRY_VERSION,
  MINIMUM_YARN_CLASSIC_VERSION,
  getYarnVersion,
  yarnAuditSupportsRegistry,
  yarnSupportsAudit,
  yarnSupportsClassicAudit,
  yarnUsesBerryTreeReport,
} from "./yarn-version.js";

/**
 * Shape of each NDJSON line emitted by `yarn npm audit --json` on Yarn 4+.
 * One object per advisory.
 * @see https://github.com/yarnpkg/berry/issues/5781
 */
interface YarnBerryV4TreeReportLine {
  value: string;
  children: {
    ID: number | string;
    Issue?: string;
    URL?: string;
    Severity: Severity;
    "Vulnerable Versions"?: string;
    "Tree Versions"?: string[];
    Dependents?: string[];
  };
}

interface YarnBerryV4Summary {
  vulnerabilities: Record<Severity, number>;
}

const BERRY_V4_LOCATOR_RE =
  /^(?<name>(?:@[^/]+\/)?[^@]+)@(?<reference>.+)$/;

function isYarnBerryV4Line(line: unknown): line is YarnBerryV4TreeReportLine {
  if (typeof line !== "object" || line === null) return false;
  const { value, children } = line as {
    value?: unknown;
    children?: unknown;
  };
  if (typeof value !== "string") return false;
  if (typeof children !== "object" || children === null) return false;
  const { Severity } = children as { Severity?: unknown };
  return typeof Severity === "string";
}

function mapBerryV4LineToAdvisory(
  line: YarnBerryV4TreeReportLine,
): ProcessedAdvisory | undefined {
  const { value: moduleName, children } = line;
  const url = typeof children.URL === "string" ? children.URL : "";
  if (!url.startsWith("https://github.com/advisories/")) {
    // Yarn 4 also emits deprecation notices (e.g. `"ID": "<pkg> (deprecation)"`);
    // they lack a GHSA URL. The exact prefix is also required because
    // `gitHubAdvisoryUrlToAdvisoryId` reads the id from `split("/")[4]`.
    return;
  }
  if (typeof children.ID !== "number") {
    // Non-numeric IDs would collide on `0` inside Model's advisory maps.
    return;
  }
  return {
    id: children.ID,
    module_name: moduleName,
    severity: children.Severity,
    github_advisory_id: gitHubAdvisoryUrlToAdvisoryId(url),
    url: url as ProcessedAdvisory["url"],
    findings: [
      {
        paths: mapBerryV4DependentsToPaths(moduleName, children.Dependents),
      },
    ],
  };
}

function mapBerryV4DependentsToPaths(
  moduleName: string,
  dependents: string[] | undefined,
): string[] {
  if (!dependents || dependents.length === 0) {
    return [moduleName];
  }

  const paths = new Set<string>();
  for (const dependent of dependents) {
    const parsedDependent = parseBerryV4Locator(dependent);
    if (!parsedDependent) {
      paths.add(`${dependent}>${moduleName}`);
      continue;
    }

    if (parsedDependent.reference === "workspace:.") {
      // Root workspace is the project itself — collapse to a bare module name
      // so paths match single-package projects. Non-root workspaces keep their
      // name as the path prefix so allowlist entries can target specific
      // workspaces (e.g. `GHSA-…|my-workspace>qs`).
      paths.add(moduleName);
      continue;
    }

    paths.add(`${parsedDependent.name}>${moduleName}`);
  }
  return [...paths];
}

function parseBerryV4Locator(locator: string) {
  const match = BERRY_V4_LOCATOR_RE.exec(locator);
  return match?.groups
    ? {
        name: match.groups.name,
        reference: match.groups.reference,
      }
    : undefined;
}

function createBerryV4Summary(): YarnBerryV4Summary {
  return {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
    },
  };
}

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
  const isYarnBerryV4 =
    !isYarnClassic && yarnUsesBerryTreeReport(yarnVersion);
  const yarnName = isYarnClassic ? `Yarn` : `Yarn Berry`;
  const berrySummary = isYarnBerryV4 ? createBerryV4Summary() : undefined;

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
      if (isYarnClassic) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        printAuditData = ({ type, data }: any) => {
          if (isClassicAuditAdvisory(data, type)) {
            const severity = data.advisory.severity;
            if (severity !== "info" && levels[severity]) {
              printJson(data);
            }
          } else if (isClassicAuditSummary(data, type)) {
            printJson(data);
          }
        };
      } else if (isYarnBerryV4) {
        printAuditData = ({
          line,
          advisory,
        }: {
          line: YarnBerryV4TreeReportLine;
          advisory: ProcessedAdvisory | undefined;
        }) => {
          if (advisory && advisory.severity !== "info" && levels[advisory.severity]) {
            printJson(line);
          }
        };
      } else {
        printAuditData = ({
          metadata,
        }: {
          metadata: Yarn2And3AuditReport.AuditMetadata;
        }) => {
          printJson(metadata);
        };
      }
      break;
    }
    case "summary": {
      if (isYarnClassic) {
        printAuditData = ({
          type,
          data,
        }: {
          type: unknown;
          data: unknown;
        }) => {
          if (isClassicAuditAdvisory(data, type)) {
            printJson(data);
          }
        };
      } else if (isYarnBerryV4) {
        printAuditData = () => {};
      } else {
        printAuditData = ({
          metadata,
        }: {
          metadata: Yarn2And3AuditReport.AuditMetadata;
        }) => {
          printJson(metadata);
        };
      }
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
      } else if (isYarnBerryV4 && isYarnBerryV4Line(line)) {
        const advisory = mapBerryV4LineToAdvisory(line);

        if (advisory && berrySummary) {
          berrySummary.vulnerabilities[advisory.severity] += 1;
        }

        printAuditData(reportType === "important" ? { line, advisory } : line);

        if (advisory) {
          model.process(advisory);
        }
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
  if (
    berrySummary &&
    (reportType === "important" || reportType === "summary")
  ) {
    printJson(berrySummary);
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

/**
 * Run audit-ci with Yarn Classic or Yarn Berry.
 */
export async function audit(config: AuditCiConfig, reporter = reportAudit) {
  const fullConfig = mapAuditCiConfigToAuditCiFullConfig(config);
  return await auditWithFullConfig(fullConfig, reporter);
}
