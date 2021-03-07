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

    // only for npm ver. 6
    if (advisory.findings) {
      advisory.findings.forEach((finding) =>
        finding.paths.forEach((path) => {
          if (this.allowlist.paths.includes(`${advisory.id}|${path}`)) {
            this.allowlistedPathsFound.push(`${advisory.id}|${path}`);
          }
        })
      );

      if (
        advisory.findings.every((finding) =>
          finding.paths.every((path) =>
            this.allowlist.paths.includes(`${advisory.id}|${path}`)
          )
        )
      ) {
        return;
      }
    }

    // only for npm ver. 7
    if (advisory.nodes) {
      const nodes = advisory.nodes
        .map((node) => node.split(/\//)[1])
        .filter((node) =>
          this.allowlist.paths.find((path) => path.includes(node))
        );

      nodes.forEach((path) => {
        this.allowlistedPathsFound.push(`${advisory.id}|${path}`);
      });
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
    Object.values(parsedOutput.vulnerabilities)
      .map((a) => ({
        id: a.via[0].source ? a.via[0].source : a.via[0],
        module_name: a.name,
        severity: a.severity,
        nodes: a.nodes,
      }))
      .forEach((a) => this.process(a));
    return this.getSummary();
  }

  getSummary(advisoryMapper = (a) => a.id) {
    const foundSeverities = new Set();
    this.advisoriesFound.forEach((curr) => foundSeverities.add(curr.severity));
    const failedLevelsFound = [...foundSeverities.values()];
    failedLevelsFound.sort();

    const advisoriesFound = [
      ...new Set(this.advisoriesFound.map(advisoryMapper)),
    ];

    const allowlistedAdvisoriesNotFound = this.allowlist.advisories.filter(
      (id) => !this.allowlistedAdvisoriesFound.includes(id)
    );
    const allowlistedModulesNotFound = this.allowlist.modules.filter(
      (id) => !this.allowlistedModulesFound.includes(id)
    );
    const allowlistedPathsNotFound = this.allowlist.paths.filter(
      (id) =>
        !this.allowlistedPathsFound.find((allowed) => allowed.includes(id))
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
