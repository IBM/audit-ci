import type { GitHubAdvisoryId, PNPMAuditReport } from "audit-types";
import { execSync } from "child_process";
import * as semver from "semver";
import { blue, yellow } from "./colors.js";
import { ReportConfig, reportAudit, runProgram } from "./common.js";
import {
  AuditCiConfig,
  AuditCiFullConfig,
  mapAuditCiConfigToAuditCiFullConfig,
} from "./config.js";
import Model, { type Summary } from "./model.js";

const MINIMUM_PNPM_AUDIT_REGISTRY_VERSION = "5.4.0";

async function runPnpmAudit(
  config: AuditCiFullConfig,
): Promise<PNPMAuditReport.AuditResponse> {
  const {
    directory,
    registry,
    _pnpm,
    "skip-dev": skipDevelopmentDependencies,
    "extra-args": extraArguments,
  } = config;
  const pnpmExec = _pnpm || "pnpm";

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const stdoutBuffer: any = {};
  function outListener(data: unknown) {
    // Object.assign is used here instead of the spread operator for minor performance gains.
    Object.assign(stdoutBuffer, data);
  }

  const stderrBuffer: unknown[] = [];
  function errorListener(line: unknown) {
    stderrBuffer.push(line);
  }

  const arguments_ = ["audit", "--json"];
  if (registry) {
    const pnpmVersion = getPnpmVersion(directory);

    if (pnpmAuditSupportsRegistry(pnpmVersion)) {
      arguments_.push("--registry", registry);
    } else {
      console.warn(
        yellow,
        `Update PNPM to version >=${MINIMUM_PNPM_AUDIT_REGISTRY_VERSION} to use the --registry flag`,
      );
    }
  }
  if (skipDevelopmentDependencies) {
    arguments_.push("--prod");
  }
  if (extraArguments) {
    arguments_.push(...extraArguments);
  }
  const options = { cwd: directory };
  await runProgram(pnpmExec, arguments_, options, outListener, errorListener);
  if (stderrBuffer.length > 0) {
    throw new Error(
      `Invocation of pnpm audit failed:\n${stderrBuffer.join("\n")}`,
    );
  }
  return stdoutBuffer;
}

function printReport(
  parsedOutput: PNPMAuditReport.Audit,
  levels: AuditCiFullConfig["levels"],
  reportType: "full" | "important" | "summary",
  outputFormat: "text" | "json",
) {
  const printReportObject = (text: string, object: unknown) => {
    if (outputFormat === "text") {
      console.log(blue, text);
    }
    console.log(JSON.stringify(object, undefined, 2));
  };
  switch (reportType) {
    case "full": {
      printReportObject("PNPM audit report JSON:", parsedOutput);
      break;
    }
    case "important": {
      const { advisories, metadata } = parsedOutput;

      const advisoryKeys = Object.keys(advisories) as GitHubAdvisoryId[];

      const relevantAdvisoryLevels = advisoryKeys.filter((advisory) => {
        const severity = advisories[advisory].severity;
        return severity !== "info" && levels[severity];
      });

      const relevantAdvisories: Record<string, PNPMAuditReport.Advisory> = {};
      for (const advisory of relevantAdvisoryLevels) {
        relevantAdvisories[advisory] = advisories[advisory];
      }

      const keyFindings = {
        advisories: relevantAdvisories,
        metadata: metadata,
      };
      printReportObject("PNPM audit report results:", keyFindings);
      break;
    }
    case "summary": {
      printReportObject("PNPM audit report summary:", parsedOutput.metadata);
      break;
    }
    default: {
      throw new Error(
        `Invalid report type: ${reportType}. Should be \`['important', 'full', 'summary']\`.`,
      );
    }
  }
}

export function report(
  parsedOutput: PNPMAuditReport.Audit,
  config: AuditCiFullConfig,
  reporter: (
    summary: Summary,
    config: ReportConfig,
    audit?: PNPMAuditReport.Audit,
  ) => Summary,
) {
  const {
    levels,
    "report-type": reportType,
    "output-format": outputFormat,
  } = config;
  printReport(parsedOutput, levels, reportType, outputFormat);
  const model = new Model(config);
  const summary = model.load(parsedOutput);
  return reporter(summary, config, parsedOutput);
}

/**
 * Audit your PNPM project!
 *
 * @returns Returns the audit report summary on resolve, `Error` on rejection.
 */
export async function auditWithFullConfig(
  config: AuditCiFullConfig,
  reporter = reportAudit,
) {
  const parsedOutput = await runPnpmAudit(config);
  if ("error" in parsedOutput) {
    const { code, summary } = parsedOutput.error;
    throw new Error(`code ${code}: ${summary}`);
  }
  return report(parsedOutput, config, reporter);
}

/**
 * Run audit-ci with PNPM.
 */
export async function audit(config: AuditCiConfig, reporter = reportAudit) {
  const fullConfig = mapAuditCiConfigToAuditCiFullConfig(config);
  return await auditWithFullConfig(fullConfig, reporter);
}

function pnpmAuditSupportsRegistry(
  pnpmVersion: string | semver.SemVer,
): boolean {
  return semver.gte(pnpmVersion, MINIMUM_PNPM_AUDIT_REGISTRY_VERSION);
}

function getPnpmVersion(cwd?: string): string {
  return execSync("pnpm -v", { cwd }).toString().replace("\n", "");
}
