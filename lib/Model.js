const { matchString, gitHubAdvisoryUrlToAdvisoryId } = require("./common");

const SUPPORTED_SEVERITY_LEVELS = new Set([
  "critical",
  "high",
  "moderate",
  "low",
]);

class Model {
  constructor(config) {
    const unsupported = Object.keys(config.levels).filter(
      (curr) => !SUPPORTED_SEVERITY_LEVELS.has(curr)
    );
    if (unsupported.length) {
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

    /** @type {Set<string>} */
    const allowlistedPathsFoundSet = new Set();

    advisory.findings
      .flatMap((finding) =>
        finding.paths.map((path) => `${advisory.github_advisory_id}|${path}`)
      )
      .filter((path) =>
        this.allowlist.paths.some((allowedPath) =>
          matchString(allowedPath, path)
        )
      )
      .forEach((path) => {
        if (!allowlistedPathsFoundSet.has(path)) {
          allowlistedPathsFoundSet.add(path);
        }
      });

    const isAllowListed = advisory.findings.every((finding) =>
      finding.paths.every((path) =>
        this.allowlist.paths.some((allowedPath) =>
          matchString(allowedPath, `${advisory.github_advisory_id}|${path}`)
        )
      )
    );

    this.allowlistedPathsFound.push(...Array.from(allowlistedPathsFoundSet));

    if (isAllowListed) {
      return;
    }

    this.advisoriesFound.push(advisory);
  }

  load(parsedOutput) {
    /** NPM 6 */

    if (parsedOutput.advisories) {
      Object.values(parsedOutput.advisories).forEach((a) => {
        // eslint-disable-next-line no-param-reassign, prefer-destructuring
        a.github_advisory_id = gitHubAdvisoryUrlToAdvisoryId(a.url);
        this.process(a);
      });
      return this.getSummary();
    }

    /** NPM 7+ */

    /** @type {Map<string, { id: number; module_name: string; url: string; findingsSet: Set<string>; findings: { paths: string[]}[]}>} */
    const advisoryMap = new Map();
    // First, let's deal with building a structure that's as close to NPM 6 as we can
    // without dealing with the findings.
    Object.values(parsedOutput.vulnerabilities).forEach((vulnerability) => {
      /** @type {{ via: (string | object)[], isDirect: boolean }} */
      const { via: vias, isDirect } = vulnerability;
      /** @type {string[]} */
      vias
        .filter((via) => typeof via !== "string")
        .forEach((via) => {
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
        });
    });

    // Now, all we have to deal with is develop the 'findings' property by traversing
    // the audit tree.

    const prependPath = (newItem, currPath) => `${newItem}>${currPath}`;

    /** @type {Map<string, string[]>} */
    const visitedModules = new Map();

    Object.entries(parsedOutput.vulnerabilities).forEach((vuln) => {
      // Did this approach rather than destructuring within the forEach to type vulnerability
      const moduleName = vuln[0];
      /** @type {{ via: (string | object)[]; isDirect: boolean; effects: string[] }} */
      const vulnerability = vuln[1];
      const { via: vias, isDirect } = vulnerability;

      if (vias.length === 0 || typeof vias[0] === "string") {
        return;
      }

      /** @type {Set<string>} */
      const visited = new Set();

      function recursiveMagic(
        /** @type {{ name: string; via: (string | object)[]; isDirect: boolean; effects: string[] }} */ cVuln,
        /** @type {string} */ dependencyPath
      ) {
        if (visitedModules.has(cVuln.name)) {
          return visitedModules.get(cVuln.name).map((name) => {
            const resultWithExtraCarat = prependPath(name, dependencyPath);
            return resultWithExtraCarat.substring(
              0,
              resultWithExtraCarat.length - 1
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
          return [newPath.substring(0, newPath.length - 1)];
        }
        /** @type {string[]} */
        const result = cVuln.effects.flatMap((effect) =>
          recursiveMagic(parsedOutput.vulnerabilities[effect], newPath)
        );
        return result;
      }

      const result = recursiveMagic(vulnerability, "");
      if (isDirect) {
        result.push(moduleName);
      }
      vias
        .filter((via) => typeof via !== "string")
        .map((via) => via.source)
        .forEach((advisory) => {
          result.forEach((path) => {
            advisoryMap.get(advisory).findingsSet.add(path);
          });
        });
      // Optimization to prevent extra traversals.
      visitedModules.set(moduleName, result);
    });

    advisoryMap.forEach((advisory) => {
      // eslint-disable-next-line no-param-reassign
      advisory.findings = [{ paths: Array.from(advisory.findingsSet) }];
      // eslint-disable-next-line no-param-reassign
      delete advisory.findingsSet;
      this.process(advisory);
    });
    return this.getSummary();
  }

  getSummary(advisoryMapper = (a) => a.github_advisory_id) {
    const foundSeverities = new Set();
    this.advisoriesFound.forEach((curr) => foundSeverities.add(curr.severity));
    const failedLevelsFound = Array.from(foundSeverities);
    failedLevelsFound.sort();

    const advisoriesFound = Array.from(
      new Set(this.advisoriesFound.map(advisoryMapper))
    );

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

    return {
      advisoriesFound,
      failedLevelsFound,
      allowlistedAdvisoriesNotFound,
      allowlistedModulesNotFound,
      allowlistedPathsNotFound,
      allowlistedAdvisoriesFound: this.allowlistedAdvisoriesFound,
      allowlistedModulesFound: this.allowlistedModulesFound,
      allowlistedPathsFound: this.allowlistedPathsFound,
    };
  }
}

module.exports = Model;
