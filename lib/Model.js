const { matchString } = require("./common");

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

    if (this.allowlist.advisories.includes(advisory.id)) {
      if (!this.allowlistedAdvisoriesFound.includes(advisory.id)) {
        this.allowlistedAdvisoriesFound.push(advisory.id);
      }
      return;
    }

    /** @type {Set<string>} */
    const allowlistedPathsFoundSet = new Set();

    advisory.findings
      .flatMap((finding) =>
        finding.paths.map((path) => `${advisory.id}|${path}`)
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
          matchString(allowedPath, `${advisory.id}|${path}`)
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
    // only for npm ver. 6
    if (parsedOutput.advisories) {
      Object.values(parsedOutput.advisories).forEach((a) => this.process(a));
      return this.getSummary();
    }

    // only for npm ver. 7
    const result = Object.keys(parsedOutput.vulnerabilities)
      .flatMap((key, index) => {
        const vulnerability = parsedOutput.vulnerabilities[key];
        let { via } = vulnerability;

        if (typeof via[0] === "string") {
          // Keep a note of what packages we've visited to avoid infinite loops
          // where packages reference each other.
          const visitedNodes = new Set();
          /** @type {string} */
          const packageBranch = [vulnerability.name];
          do {
            const packageName = via.find((n) => !visitedNodes.has(n)) || via[0];
            visitedNodes.add(packageName);
            via = parsedOutput.vulnerabilities[packageName].via;
            packageBranch.push(packageName);
          } while (typeof via[0] === "string");
          // This handles the edge case of an advisory tree having an incomplete `via` path.
          if (via.length) {
            const packageBranchAsString = packageBranch
              .filter(Boolean)
              .join(">");
            // TODO: Something with this
            (via[index] || via[0]).paths = packageBranchAsString;
          }
        }
        // This handles the edge case of an advisory tree having an incomplete `via` path.
        if (via.length === 0 && Array.isArray(via)) {
          return undefined;
        }
        return via
          .filter((v) => Boolean(v.source))
          .map((v) => ({
            id: v.source,
            module_name: vulnerability.name,
            severity: vulnerability.severity,
            nodes: vulnerability.nodes,
            findings: Array.from(
              new Set(
                via
                  .map((v1) =>
                    vulnerability.name === v.name ? v1.name : v1.paths
                  )
                  .filter(Boolean)
              )
            ).map((v1) => ({ paths: [v1] })),
          }));
      })
      // Handle undefined `via`s
      .filter(Boolean);
    result.forEach((a) => this.process(a));
    return this.getSummary();
  }

  getSummary(advisoryMapper = (a) => a.id) {
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
