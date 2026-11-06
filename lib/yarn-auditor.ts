import type { YarnAudit, Yarn2And3AuditReport, YarnNpmAuditReport } from "audit-types";
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
  yarnUsesBerryTreeReport,
} from "./yarn-version.js";

function mapTreeDependentsToPaths(moduleName: string, dependents?: readonly string[]): string[] {
  if (!dependents?.length) {
    return [moduleName];
  }
  return [
    ...new Set(
      dependents.map((dependent) => {
        // Split after the package name; references can themselves contain `@`.
        const locator = /^(?<name>(?:@[^/]+\/)?[^@]+)@(?<reference>.+)$/.exec(dependent)?.groups;
        if (locator?.reference === "workspace:.") {
          return moduleName;
        }
        return `${locator?.name ?? dependent}>${moduleName}`;
      }),
    ),
  ];
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

const isClassicAuditSummary = (data: unknown, type: unknown): data is YarnAudit.AuditMetadata => {
  return type === "auditSummary";
};

type YarnReporter = (summary: Summary, config: ReportConfig) => Summary;

/** Share parsing and reporting between subprocess audits and recorded fixtures. */
function createYarnAuditSession(config: AuditCiFullConfig, yarnVersion: string) {
  const { levels, "report-type": reportType, "output-format": outputFormat } = config;
  let missingLockFile = false;
  const model = new Model(config);

  const isYarnVersionSupported = yarnSupportsAudit(yarnVersion);
  if (!isYarnVersionSupported) {
    throw new Error(
      `Yarn ${yarnVersion} not supported, must be ^${MINIMUM_YARN_CLASSIC_VERSION} or >=${MINIMUM_YARN_BERRY_VERSION}`,
    );
  }
  const isYarnClassic = yarnSupportsClassicAudit(yarnVersion);
  const isYarn4 = yarnUsesBerryTreeReport(yarnVersion);
  const yarnName = isYarnClassic ? `Yarn` : `Yarn Berry`;

  function isClassicGuard(
    _response: YarnAudit.AuditResponse | Yarn2And3AuditReport.AuditResponse,
  ): _response is YarnAudit.AuditResponse {
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
      reportType satisfies never;
      throw new Error(
        `Invalid report type: ${reportType as string}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }

  // Define a function to print based on the report type.
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
        ? ({ type, data }: any) => {
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
            if (isClassicAuditSummary(data, type)) {
              printJson(data);
            }
          }
        : ({ metadata }: { metadata: Yarn2And3AuditReport.AuditMetadata }) => {
            printJson(metadata);
          };
      break;
    }
    default: {
      reportType satisfies never;
      throw new Error(
        `Invalid report type: ${reportType as string}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }

  const treeCounts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  function outListener(
    line:
      | YarnAudit.AuditResponse
      | Yarn2And3AuditReport.AuditResponse
      | YarnNpmAuditReport.AuditResponse,
  ) {
    try {
      if ("error" in line) {
        throw new Error(line.error.summary);
      }
      if ("type" in line && line.type === "error") {
        throw new Error(line.data);
      }
      if (isYarn4) {
        if (!("children" in line)) {
          if (reportType === "full") {
            printJson(line);
          }
          return;
        }
        const { value: moduleName, children } = line;
        // Yarn includes deprecation notices in the same stream as vulnerabilities.
        // Only skip explicitly identified deprecations; missing vulnerability URLs
        // must still produce an error instead of silently passing the audit.
        if (!children.URL && children.ID === `${moduleName} (deprecation)`) {
          if (reportType === "full") {
            printJson(line);
          }
          return;
        }
        treeCounts[children.Severity]++;
        if (
          reportType === "full" ||
          (reportType === "important" && children.Severity !== "info" && levels[children.Severity])
        ) {
          printJson(line);
        }
        if (
          !children.URL &&
          (children.Severity === "info" || levels[children.Severity]) &&
          !model.allowlist.modules.includes(moduleName)
        ) {
          throw new Error(
            `Cannot identify Yarn advisory for ${moduleName}: ${children.Issue} (missing URL).`,
          );
        }
        model.process({
          id: typeof children.ID === "number" ? children.ID : 0,
          module_name: moduleName,
          title: children.Issue,
          severity: children.Severity,
          url: children.URL ?? "",
          findings: [
            {
              paths: mapTreeDependentsToPaths(moduleName, children.Dependents),
            },
          ],
        });
        return;
      }
      if ("children" in line) {
        throw new Error("Unexpected Yarn advisory tree response.");
      }
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
          for (const advisory of Object.values<Yarn2And3AuditReport.Advisory>(line.advisories)) {
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

  const stderrBuffer: any[] = [];
  function errorListener(line: any) {
    stderrBuffer.push(line);

    if (line.type === "error") {
      throw new Error(line.data);
    }
  }
  function finish(reporter: YarnReporter = reportAudit): Summary {
    if (isYarn4 && (reportType === "summary" || reportType === "important")) {
      printJson({ vulnerabilities: treeCounts });
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
  return { outListener, errorListener, finish };
}

export function reportClassic(
  lines: readonly YarnAudit.AuditResponse[],
  config: AuditCiFullConfig,
  reporter: YarnReporter = reportAudit,
): Summary {
  const session = createYarnAuditSession(config, "1.22.22");
  for (const line of lines) {
    session.outListener(line);
  }
  return session.finish(reporter);
}

export function reportBerry(
  output: Yarn2And3AuditReport.AuditResponse,
  config: AuditCiFullConfig,
  reporter: YarnReporter = reportAudit,
): Summary {
  const session = createYarnAuditSession(config, "2.4.0");
  session.outListener(output);
  return session.finish(reporter);
}

/** Run a Yarn audit and report its streamed response. */
export async function auditWithFullConfig(
  config: AuditCiFullConfig,
  reporter: YarnReporter = reportAudit,
): Promise<Summary> {
  const {
    registry,
    "skip-dev": skipDevelopmentDependencies,
    _yarn,
    directory,
    "extra-args": extraArguments,
  } = config;
  const yarnExec = _yarn || "yarn";
  const yarnVersion = getYarnVersion(yarnExec, directory);
  const session = createYarnAuditSession(config, yarnVersion);
  const isYarnClassic = yarnSupportsClassicAudit(yarnVersion);
  const options = { cwd: directory };
  const cliArguments = isYarnClassic
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
      cliArguments.push("--registry", registry);
    } else {
      console.warn(yellow, "Yarn audit does not support the registry flag yet.");
    }
  }
  if (extraArguments) {
    cliArguments.push(...extraArguments);
  }
  await runProgram(yarnExec, cliArguments, options, session.outListener, session.errorListener);
  return session.finish(reporter);
}

/**
 * Run audit-ci with Yarn Classic or Yarn Berry.
 */
export async function audit(config: AuditCiConfig, reporter = reportAudit) {
  const fullConfig = mapAuditCiConfigToAuditCiFullConfig(config);
  return await auditWithFullConfig(fullConfig, reporter);
}
