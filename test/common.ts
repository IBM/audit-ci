import path from "path";
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
    levels: {
      low: false,
      moderate: false,
      high: false,
      critical: false,
    },
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
