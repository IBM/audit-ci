import type { GitHubAdvisoryId, NPMAuditReportV2 } from "audit-types";
import Allowlist from "./allowlist.js";
import {
  gitHubAdvisoryUrlToAdvisoryId,
  matchString,
  partition,
} from "./common.js";
import type { AuditCiFullConfig } from "./config.js";
import type { VulnerabilityLevels } from "./map-vulnerability.js";
import type { DeepReadonly, DeepWriteable } from "./types.js";

const SUPPORTED_SEVERITY_LEVELS = new Set([
  "critical",
  "high",
  "moderate",
  "low",
]);

const prependPath = <N extends string, C extends string>(
  newItem: N,
  currentPath: C,
): `${N}>${C}` => `${newItem}>${currentPath}`;

const isVia = <T>(via: T | string): via is T => {
  return typeof via !== "string";
};

export interface Summary {
  advisoriesFound: GitHubAdvisoryId[];
  failedLevelsFound: ("low" | "moderate" | "high" | "critical")[];
  allowlistedAdvisoriesNotFound: string[];
  allowlistedModulesNotFound: string[];
  allowlistedPathsNotFound: string[];
  allowlistedAdvisoriesFound: GitHubAdvisoryId[];
  allowlistedModulesFound: string[];
  allowlistedPathsFound: string[];
  advisoryPathsFound: string[];
}

interface ProcessedAdvisory {
  id: number;
  github_advisory_id: GitHubAdvisoryId;
  severity: "critical" | "high" | "moderate" | "low" | "info";
  module_name: string;
  url: `https://github.com/advisories/${GitHubAdvisoryId}`;
  findings: { paths: string[] }[];
}

// These are hre to simplify testing by requiring only the relevant parts of the
// audit report.
interface PartialNPMAuditReportV1Audit {
  advisories: Readonly<Record<GitHubAdvisoryId, ProcessedAdvisory>>;
}
interface PartialPNPMAuditReportAudit {
  advisories: Readonly<Record<GitHubAdvisoryId, ProcessedAdvisory>>;
}
interface PartialNPMAuditReportV2Audit {
  vulnerabilities: Readonly<
    Record<
      string,
      Pick<NPMAuditReportV2.Advisory, "name" | "isDirect" | "via" | "effects"> &
        Partial<NPMAuditReportV2.Advisory>
    >
  >;
}

class Model {
  failingSeverities: {
    [K in keyof VulnerabilityLevels]: VulnerabilityLevels[K];
  };
  allowlist: Allowlist;
  allowlistedModulesFound: string[];
  allowlistedAdvisoriesFound: GitHubAdvisoryId[];
  allowlistedPathsFound: `${GitHubAdvisoryId}|${string}`[];
  advisoriesFound: ProcessedAdvisory[];
  advisoryPathsFound: string[];

  constructor(config: Pick<AuditCiFullConfig, "allowlist" | "levels">) {
    const unsupported = Object.keys(config.levels).filter(
      (level) => !SUPPORTED_SEVERITY_LEVELS.has(level),
    );
    if (unsupported.length > 0) {
      throw new Error(
        `Unsupported severity levels found: ${unsupported.sort().join(", ")}`,
      );
    }
    this.failingSeverities = config.levels;

    this.allowlist = config.allowlist;

    this.allowlistedModulesFound = [];
    this.allowlistedAdvisoriesFound = [];
    this.allowlistedPathsFound = [];
    this.advisoriesFound = [];
    this.advisoryPathsFound = [];
  }

  process(advisory: ProcessedAdvisory) {
    const {
      severity,
      module_name: moduleName,
      github_advisory_id: githubAdvisoryId,
      findings,
    } = advisory;
    if (severity !== "info" && !this.failingSeverities[severity]) {
      return;
    }

    if (this.allowlist.modules.includes(moduleName)) {
      if (!this.allowlistedModulesFound.includes(moduleName)) {
        this.allowlistedModulesFound.push(moduleName);
      }
      return;
    }

    if (this.allowlist.advisories.includes(githubAdvisoryId)) {
      if (!this.allowlistedAdvisoriesFound.includes(githubAdvisoryId)) {
        this.allowlistedAdvisoriesFound.push(githubAdvisoryId);
      }
      return;
    }

    const allowlistedPathsFoundSet = new Set<`${GitHubAdvisoryId}|${string}`>();

    const flattenedPaths = findings.flatMap((finding) => finding.paths);
    const flattenedAllowlist = flattenedPaths.map(
      (path) => `${githubAdvisoryId}|${path}` as const,
    );
    const { truthy, falsy } = partition(flattenedAllowlist, (path) =>
      this.allowlist.paths.some((allowedPath) =>
        matchString(allowedPath, path),
      ),
    );
    for (const path of truthy) {
      allowlistedPathsFoundSet.add(path);
    }

    this.allowlistedPathsFound.push(...allowlistedPathsFoundSet);

    const isAllowListed = falsy.length === 0;
    if (isAllowListed) {
      return;
    }

    this.advisoriesFound.push(advisory);
    this.advisoryPathsFound.push(...falsy);
  }

  load(
    parsedOutput:
      | PartialNPMAuditReportV2Audit
      | PartialNPMAuditReportV1Audit
      | PartialPNPMAuditReportAudit,
  ) {
    /** NPM 6 & PNPM */
    if ("advisories" in parsedOutput && parsedOutput.advisories) {
      for (const advisory of Object.values<
        DeepWriteable<
          | PartialNPMAuditReportV1Audit["advisories"][GitHubAdvisoryId]
          | PartialPNPMAuditReportAudit["advisories"][GitHubAdvisoryId]
        >
      >(parsedOutput.advisories)) {
        advisory.github_advisory_id = gitHubAdvisoryUrlToAdvisoryId(
          advisory.url,
        );
        // PNPM paths have a leading `.>`
        // "paths": [
        //  ".>module-name"
        //]
        for (const finding of advisory.findings) {
          finding.paths = finding.paths.map((path) => path.replace(".>", ""));
        }
        this.process(advisory);
      }
      return this.getSummary();
    }

    /** NPM 7+ */
    if ("vulnerabilities" in parsedOutput && parsedOutput.vulnerabilities) {
      const advisoryMap = new Map<
        number,
        ProcessedAdvisory & {
          findingsSet: Set<string>;
        }
      >();
      // First, let's deal with building a structure that's as close to NPM 6 as we can
      // without dealing with the findings.
      for (const vulnerability of Object.values<
        PartialNPMAuditReportV2Audit["vulnerabilities"][GitHubAdvisoryId]
      >(parsedOutput.vulnerabilities)) {
        const { via: vias, isDirect } = vulnerability;
        // https://github.com/microsoft/TypeScript/issues/33591
        for (const via of vias as Array<string | NPMAuditReportV2.Via>) {
          if (!isVia(via)) {
            continue;
          }
          const { source, url, name, severity } = via;
          if (!advisoryMap.has(source)) {
            advisoryMap.set(source, {
              id: source,
              github_advisory_id: gitHubAdvisoryUrlToAdvisoryId(url),
              module_name: name,
              severity: severity,
              url: url,
              // This will eventually be an array.
              // However, to improve the performance of deduplication,
              // start with a set.
              findingsSet: new Set(isDirect ? [name] : []),
              findings: [],
            });
          }
        }
      }

      // Now, all we have to deal with is develop the 'findings' property by traversing
      // the audit tree.

      const visitedModules = new Map<string, string[]>();

      for (const vuln of Object.entries<
        DeepReadonly<
          PartialNPMAuditReportV2Audit["vulnerabilities"][GitHubAdvisoryId]
        >
      >(parsedOutput.vulnerabilities)) {
        // Did this approach rather than destructuring within the forEach to type vulnerability
        const moduleName = vuln[0];
        const vulnerability = vuln[1];
        const { via: vias, isDirect } = vulnerability;

        if (vias.length === 0 || typeof vias[0] === "string") {
          continue;
        }

        const visited = new Set<string>();

        const recursiveMagic = (
          cVuln: DeepReadonly<
            PartialNPMAuditReportV2Audit["vulnerabilities"][GitHubAdvisoryId]
          >,
          dependencyPath: string,
        ): string[] => {
          const visitedModule = visitedModules.get(cVuln.name);
          if (visitedModule) {
            return visitedModule.map((name) => {
              const resultWithExtraCarat = prependPath(name, dependencyPath);
              return resultWithExtraCarat.slice(
                0,
                Math.max(0, resultWithExtraCarat.length - 1),
              );
            });
          }

          if (visited.has(cVuln.name)) {
            // maybe undefined and filter?
            return [dependencyPath];
          }
          visited.add(cVuln.name);
          const newPath = prependPath(cVuln.name, dependencyPath);
          if (cVuln.effects.length === 0) {
            return [newPath.slice(0, Math.max(0, newPath.length - 1))];
          }
          const result = cVuln.effects.flatMap((effect) =>
            recursiveMagic(parsedOutput.vulnerabilities[effect], newPath),
          );
          return result;
        };

        const result = recursiveMagic(vulnerability, "");
        if (isDirect) {
          result.push(moduleName);
        }
        const advisories = (
          (vias as Array<string | NPMAuditReportV2.Via>).filter(
            (via) => typeof via !== "string",
          ) as NPMAuditReportV2.Via[]
        )
          .map((via) => via.source)
          // Filter boolean makes the next line non-nullable.
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          .map((id) => advisoryMap.get(id)!)
          .filter(Boolean);
        for (const advisory of advisories) {
          for (const path of result) {
            advisory.findingsSet.add(path);
          }
        }
        // Optimization to prevent extra traversals.
        visitedModules.set(moduleName, result);
      }
      for (const [, advisory] of advisoryMap) {
        advisory.findings = [{ paths: [...advisory.findingsSet] }];
        // @ts-expect-error don't care about findingSet anymore
        delete advisory.findingsSet;
        this.process(advisory);
      }
    }
    return this.getSummary();
  }

  getSummary(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    advisoryMapper: (advisory: any) => GitHubAdvisoryId = (a) =>
      a.github_advisory_id,
  ) {
    // Clean up the data structures for more consistent output.
    this.advisoriesFound.sort();
    this.advisoryPathsFound = [...new Set(this.advisoryPathsFound)].sort();
    this.allowlistedAdvisoriesFound.sort();
    this.allowlistedModulesFound.sort();
    this.allowlistedPathsFound.sort();

    const foundSeverities = new Set<"low" | "moderate" | "high" | "critical">();
    for (const { severity } of this.advisoriesFound) {
      if (severity !== "info") {
        foundSeverities.add(severity);
      }
    }
    const failedLevelsFound = [...foundSeverities].sort();

    const advisoriesFound = [
      ...new Set(this.advisoriesFound.map((a) => advisoryMapper(a))),
    ].sort();

    const allowlistedAdvisoriesNotFound = this.allowlist.advisories
      .filter((id) => !this.allowlistedAdvisoriesFound.includes(id))
      .sort();
    const allowlistedModulesNotFound = this.allowlist.modules
      .filter((id) => !this.allowlistedModulesFound.includes(id))
      .sort();
    const allowlistedPathsNotFound = this.allowlist.paths
      .filter(
        (id) =>
          !this.allowlistedPathsFound.some((foundPath) =>
            matchString(id, foundPath),
          ),
      )
      .sort();

    const summary: Summary = {
      advisoriesFound,
      failedLevelsFound,
      allowlistedAdvisoriesNotFound,
      allowlistedModulesNotFound,
      allowlistedPathsNotFound,
      allowlistedAdvisoriesFound: this.allowlistedAdvisoriesFound,
      allowlistedModulesFound: this.allowlistedModulesFound,
      allowlistedPathsFound: this.allowlistedPathsFound,
      advisoryPathsFound: this.advisoryPathsFound,
    };
    return summary;
  }
}

export default Model;
