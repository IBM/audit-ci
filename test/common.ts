import { readFileSync } from "node:fs";
import path from "node:path";
import type { YarnAudit, Yarn2And3AuditReport } from "audit-types";
import Allowlist from "../lib/allowlist.js";
import { AuditCiFullConfig } from "../lib/config.js";
import { mapVulnerabilityLevelInput } from "../lib/map-vulnerability.js";
import { Summary } from "../lib/model.js";

export function summaryWithDefault(additions: Partial<Summary> = {}) {
  const summary = {
    allowlistedModulesFound: [],
    allowlistedAdvisoriesFound: [],
    allowlistedAdvisoriesNotFound: [],
    allowlistedPathsFound: [],
    allowlistedModulesNotFound: [],
    allowlistedPathsNotFound: [],
    failedLevelsFound: [],
    advisoriesFound: [],
    advisoryPathsFound: [],
  };
  return { ...summary, ...additions };
}

export function config(
  additions: Omit<Partial<AuditCiFullConfig>, "levels"> & {
    levels?: Partial<AuditCiFullConfig["levels"]>;
  } & Required<Pick<AuditCiFullConfig, "package-manager">>,
): AuditCiFullConfig {
  const defaultConfig = {
    levels: { low: false, moderate: false, high: false, critical: false },
    "report-type": "important",
    allowlist: new Allowlist(),
    "show-not-found": false,
    "retry-count": 5,
    directory: "./",
    registry: undefined,
    "pass-enoaudit": false,
    report: false,
    summary: false,
    "show-found": false,
    "output-format": "text",
    "skip-dev": false,
    "extra-args": [],
  } satisfies Partial<AuditCiFullConfig>;
  const levels = mapVulnerabilityLevelInput(additions.levels || {});
  return {
    ...defaultConfig,
    ...additions,
    levels: { ...defaultConfig.levels, ...levels },
  };
}

const __dirname = path.dirname(new URL(import.meta.url).pathname);

export function testDirectory(s: string) {
  return path.resolve(__dirname, s);
}

export function readYarnClassicAuditOutput(directoryName: string): YarnAudit.AuditResponse[] {
  const filePath = path.join(testDirectory(directoryName), "output.jsonl");
  return readFileSync(filePath, "utf8")
    .trim()
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as YarnAudit.AuditResponse);
}

export function readYarnBerryAuditOutput(
  directoryName: string,
): Yarn2And3AuditReport.AuditResponse {
  const filePath = path.join(testDirectory(directoryName), "output.json");
  return JSON.parse(readFileSync(filePath, "utf8")) as Yarn2And3AuditReport.AuditResponse;
}

export function getErrorMessages(error: unknown): string {
  if (!(error instanceof Error)) {
    return String(error);
  }
  const messages = [error.message];
  let cause: unknown = error.cause;
  while (cause instanceof Error) {
    messages.push(cause.message);
    cause = cause.cause;
  }
  return messages.join(" ");
}
