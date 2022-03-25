import Allowlist from "./allowlist";
import {
  gitHubAdvisoryUrlToAdvisoryId,
  matchString,
  partition,
} from "./common";
import { AuditCiConfig } from "./config";
import { VulnerabilityLevels } from "./map-vulnerability";

const SUPPORTED_SEVERITY_LEVELS = new Set([
  "critical",
  "high",
  "moderate",
  "low",
]);

const prependPath = (newItem: string, currentPath: string) =>
  `${newItem}>${currentPath}`;

export interface Summary {
  advisoriesFound: string[];
  failedLevelsFound: string[];
  allowlistedAdvisoriesNotFound: string[];
  allowlistedModulesNotFound: string[];
  allowlistedPathsNotFound: string[];
  allowlistedAdvisoriesFound: string[];
  allowlistedModulesFound: string[];
  allowlistedPathsFound: string[];
  advisoryPathsFound: string[];
}

class Model {
  failingSeverities: {
    [K in keyof VulnerabilityLevels]: VulnerabilityLevels[K];
  };
  allowlist: Allowlist;
  allowlistedModulesFound: string[];
  allowlistedAdvisoriesFound: string[];
  allowlistedPathsFound: string[];
  advisoriesFound: any[];
  advisoryPathsFound: string[];

  constructor(config: AuditCiConfig) {
    const unsupported = Object.keys(config.levels).filter(
      (level) => !SUPPORTED_SEVERITY_LEVELS.has(level)
    );
    if (unsupported.length > 0) {
      throw new Error(
        `Unsupported severity levels found: ${unsupported.sort().join(", ")}`
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

  process(advisory) {
    if (!this.failingSeverities[advisory.severity]) {
      return;
    }

    if (this.allowlist.modules.includes(advisory.module_name)) {
      if (!this.allowlistedModulesFound.includes(advisory.module_name)) {
        this.allowlistedModulesFound.push(advisory.module_name);
      }
      return;
    }

    if (this.allowlist.advisories.includes(advisory.github_advisory_id)) {
      if (
        !this.allowlistedAdvisoriesFound.includes(advisory.github_advisory_id)
      ) {
        this.allowlistedAdvisoriesFound.push(advisory.github_advisory_id);
      }
      return;
    }

    const allowlistedPathsFoundSet = new Set<string>();

    const flattenedPaths: string[] = advisory.findings.flatMap(
      (finding) => finding.paths
    );
    const flattenedAllowlist = flattenedPaths.map(
      (path: string) => `${advisory.github_advisory_id}|${path}`
    );
    const { truthy, falsy } = partition(flattenedAllowlist, (path) =>
      this.allowlist.paths.some((allowedPath) => matchString(allowedPath, path))
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

  load(parsedOutput) {
    /** NPM 6 */

    if (parsedOutput.advisories) {
      for (const advisory of Object.values(parsedOutput.advisories)) {
        const advisoryAny = advisory as any;
        // eslint-disable-next-line no-param-reassign, prefer-destructuring
        advisoryAny.github_advisory_id = gitHubAdvisoryUrlToAdvisoryId(
          advisoryAny.url
        );
        // PNPM paths have a leading `.>`
        // "paths": [
        //  ".>module-name"
        //]
        for (const finding of advisoryAny.findings) {
          const findingAny = finding as any;
          findingAny.paths = findingAny.paths.map((path) =>
            path.replace(".>", "")
          );
        }
        this.process(advisory);
      }
      return this.getSummary();
    }

    /** NPM 7+ & PNPM */

    // This is incomplete. Rather than filling it out, plan on consuming an external dependency to manage.
    type NPM7Vulnerability = {
      name: string;
      via: (string | object)[];
      isDirect: boolean;
      effects: string[];
    };

    const advisoryMap = new Map<
      string,
      {
        id: number;
        github_advisory_id: string;
        severity: string;
        module_name: string;
        url: string;
        findingsSet: Set<string>;
        findings: { paths: string[] }[];
      }
    >();
    // First, let's deal with building a structure that's as close to NPM 6 as we can
    // without dealing with the findings.
    for (const vulnerability of Object.values<NPM7Vulnerability>(
      parsedOutput.vulnerabilities
    )) {
      const { via: vias, isDirect } = vulnerability;
      for (const via of vias.filter(
        (via) => typeof via !== "string"
      ) as any[]) {
        if (!advisoryMap.has(via.source)) {
          advisoryMap.set(via.source, {
            id: via.source,
            github_advisory_id: gitHubAdvisoryUrlToAdvisoryId(via.url),
            module_name: via.name,
            severity: via.severity,
            url: via.url,
            // This will eventually be an array.
            // However, to improve the performance of deduplication,
            // start with a set.
            findingsSet: new Set(
              [isDirect ? via.name : undefined].filter(Boolean)
            ),
            findings: [],
          });
        }
      }
    }

    // Now, all we have to deal with is develop the 'findings' property by traversing
    // the audit tree.

    const visitedModules = new Map<string, string[]>();

    for (const vuln of Object.entries<NPM7Vulnerability>(
      parsedOutput.vulnerabilities
    )) {
      // Did this approach rather than destructuring within the forEach to type vulnerability
      const moduleName = vuln[0];
      const vulnerability = vuln[1];
      const { via: vias, isDirect } = vulnerability;

      if (vias.length === 0 || typeof vias[0] === "string") {
        continue;
      }

      const visited = new Set<string>();

      const recursiveMagic = (
        cVuln: NPM7Vulnerability,
        dependencyPath: string
      ): string[] => {
        const visitedModule = visitedModules.get(cVuln.name);
        if (visitedModule) {
          return visitedModule.map((name) => {
            const resultWithExtraCarat = prependPath(name, dependencyPath);
            return resultWithExtraCarat.slice(
              0,
              Math.max(0, resultWithExtraCarat.length - 1)
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
          recursiveMagic(parsedOutput.vulnerabilities[effect], newPath)
        );
        return result;
      };

      const result = recursiveMagic(vulnerability, "");
      if (isDirect) {
        result.push(moduleName);
      }
      const advisories = (
        vias.filter((via) => typeof via !== "string") as any[]
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

    return this.getSummary();
  }

  getSummary(advisoryMapper = (a) => a.github_advisory_id) {
    const foundSeverities = new Set<string>();
    for (const { severity } of this.advisoriesFound)
      foundSeverities.add(severity);
    const failedLevelsFound = [...foundSeverities];
    failedLevelsFound.sort();

    const advisoriesFound = [
      ...new Set(this.advisoriesFound.map((a) => advisoryMapper(a))),
    ];

    const allowlistedAdvisoriesNotFound = this.allowlist.advisories.filter(
      (id) => !this.allowlistedAdvisoriesFound.includes(id)
    );
    const allowlistedModulesNotFound = this.allowlist.modules.filter(
      (id) => !this.allowlistedModulesFound.includes(id)
    );
    const allowlistedPathsNotFound = this.allowlist.paths.filter(
      (id) =>
        !this.allowlistedPathsFound.some((foundPath) =>
          matchString(id, foundPath)
        )
    );

    this.advisoryPathsFound = [...new Set(this.advisoryPathsFound)];

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
