const { expect } = require("chai");
const Model = require("../lib/Model");
const Allowlist = require("../lib/allowlist");
const { summaryWithDefault } = require("./common");

function config(additions) {
  return { whitelist: [], advisories: [], ...additions };
}

describe("Model", () => {
  it("rejects misspelled severity levels", () => {
    expect(() => new Model(config({ levels: { critical_: true } }))).to.throw(
      "Unsupported severity levels found: critical_"
    );
    expect(
      () =>
        new Model(config({ levels: { Low: true, hgih: true, mdrate: true } }))
    ).to.throw("Unsupported severity levels found: Low, hgih, mdrate");
    expect(
      () =>
        new Model(
          config({
            levels: { mdrate: true, critical: true, hgih: true, low: true },
          })
        )
    ).to.throw("Unsupported severity levels found: hgih, mdrate");
  });

  it("returns an empty summary for an empty audit output", () => {
    const model = new Model({
      levels: { critical: true, low: true, high: true, moderate: true },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      advisories: {},
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(summaryWithDefault());
  });

  it("compute a summary", () => {
    const model = new Model({
      levels: { critical: true },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      advisories: {
        1004291: {
          id: 1004291,
          title: "Command Injection",
          module_name: "open",
          severity: "critical",
          url: "https://npmjs.com/advisories/1004291",
          findings: [{ paths: ["open"] }],
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical"],
        advisoriesFound: [1004291],
      })
    );
  });

  it("ignores severities that are set to false", () => {
    const model = new Model({
      levels: { critical: true, low: true, high: false, moderate: false },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: "A",
          module_name: "M_A",
          severity: "critical",
          url: "https://A",
          findings: [{ paths: ["M_A"] }],
        },
        2: {
          id: 2,
          title: "B",
          module_name: "M_B",
          severity: "low",
          url: "https://B",
          findings: [{ paths: ["M_B"] }],
        },
        3: {
          id: 3,
          title: "C",
          module_name: "M_C",
          severity: "moderate",
          url: "https://C",
          findings: [{ paths: ["M_C"] }],
        },
        4: {
          id: 4,
          title: "D",
          module_name: "M_D",
          severity: "high",
          url: "https://D",
          findings: [{ paths: ["M_D"] }],
        },
        5: {
          id: 5,
          title: "E",
          module_name: "M_E",
          severity: "critical",
          url: "https://E",
          findings: [{ paths: ["M_E"] }],
        },
        6: {
          id: 6,
          title: "F",
          module_name: "M_F",
          severity: "low",
          url: "https://F",
          findings: [{ paths: ["M_F"] }],
        },
        7: {
          id: 7,
          title: "G",
          module_name: "M_G",
          severity: "low",
          url: "https://G",
          findings: [{ paths: ["M_G"] }],
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical", "low"],
        advisoriesFound: [1, 2, 5, 6, 7],
      })
    );
  });

  it("ignores whitelisted modules", () => {
    const model = new Model({
      levels: { critical: true, low: true, high: true, moderate: true },
      allowlist: new Allowlist(["M_A", "M_D"]),
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: "A",
          module_name: "M_A",
          severity: "critical",
          url: "https://A",
          findings: [{ paths: ["M_A"] }],
        },
        2: {
          id: 2,
          title: "B",
          module_name: "M_B",
          severity: "low",
          url: "https://B",
          findings: [{ paths: ["M_B"] }],
        },
        3: {
          id: 3,
          title: "C",
          module_name: "M_C",
          severity: "moderate",
          url: "https://C",
          findings: [{ paths: ["M_C"] }],
        },
        4: {
          id: 4,
          title: "D",
          module_name: "M_D",
          severity: "high",
          url: "https://D",
          findings: [{ paths: ["M_D"] }],
        },
        5: {
          id: 5,
          title: "E",
          module_name: "M_E",
          severity: "critical",
          url: "https://E",
          findings: [{ paths: ["M_E"] }],
        },
        6: {
          id: 6,
          title: "F",
          module_name: "M_F",
          severity: "low",
          url: "https://F",
          findings: [{ paths: ["M_F"] }],
        },
        7: {
          id: 7,
          title: "G",
          module_name: "M_G",
          severity: "low",
          url: "https://G",
          findings: [{ paths: ["M_G"] }],
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedModulesFound: ["M_A", "M_D"],
        failedLevelsFound: ["critical", "low", "moderate"],
        advisoriesFound: [2, 3, 5, 6, 7],
      })
    );
  });

  it("ignores whitelisted advisory IDs", () => {
    const model = new Model({
      levels: { critical: true, low: true, high: true, moderate: true },
      allowlist: new Allowlist([2, 3, 6]),
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: "A",
          module_name: "M_A",
          severity: "critical",
          url: "https://A",
          findings: [{ paths: ["M_A"] }],
        },
        2: {
          id: 2,
          title: "B",
          module_name: "M_B",
          severity: "low",
          url: "https://B",
          findings: [{ paths: ["M_B"] }],
        },
        3: {
          id: 3,
          title: "C",
          module_name: "M_C",
          severity: "moderate",
          url: "https://C",
          findings: [{ paths: ["M_C"] }],
        },
        4: {
          id: 4,
          title: "D",
          module_name: "M_D",
          severity: "high",
          url: "https://D",
          findings: [{ paths: ["M_D"] }],
        },
        5: {
          id: 5,
          title: "E",
          module_name: "M_E",
          severity: "critical",
          url: "https://E",
          findings: [{ paths: ["M_E"] }],
        },
        6: {
          id: 6,
          title: "F",
          module_name: "M_F",
          severity: "low",
          url: "https://F",
          findings: [{ paths: ["M_F_1"] }],
        },
        7: {
          id: 6,
          title: "F",
          module_name: "M_F",
          severity: "low",
          url: "https://F",
          findings: [{ paths: ["M_F_2"] }],
        },
        8: {
          id: 7,
          title: "G",
          module_name: "M_G",
          severity: "low",
          url: "https://G",
          findings: [{ paths: ["M_G"] }],
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: [2, 3, 6],
        failedLevelsFound: ["critical", "high", "low"],
        advisoriesFound: [1, 4, 5, 7],
      })
    );
  });

  it("sorts the failedLevelsFound field", () => {
    const model = new Model({
      levels: { critical: true, low: true },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: "A",
          module_name: "M_A",
          severity: "low",
          url: "https://A",
          findings: [{ paths: ["M_A"] }],
        },
        2: {
          id: 2,
          title: "B",
          module_name: "M_B",
          severity: "critical",
          url: "https://B",
          findings: [{ paths: ["M_B_1"] }],
        },
        3: {
          id: 2,
          title: "B",
          module_name: "M_B",
          severity: "critical",
          url: "https://B",
          findings: [{ paths: ["M_B_2"] }],
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical", "low"],
        advisoriesFound: [1, 2],
      })
    );
  });

  it("should handle advisories that reference each other in a loop for npm 7", () => {
    const model = new Model({
      levels: { moderate: true },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      vulnerabilities: {
        package1: {
          name: "package1",
          severity: "moderate",
          via: ["package2", "package3"],
          effects: ["package2"],
          range: ">=3.0.1",
          nodes: ["node_modules/package1"],
          fixAvailable: {
            name: "package2",
            version: "3.0.1",
            isSemVerMajor: true,
          },
        },
        package2: {
          name: "package2",
          severity: "moderate",
          via: ["package1"],
          effects: ["package1"],
          range: ">=3.0.2",
          nodes: ["node_modules/package2"],
          fixAvailable: {
            name: "package2",
            version: "3.0.1",
            isSemVerMajor: true,
          },
        },
        package3: {
          name: "package3",
          severity: "moderate",
          via: [
            {
              source: 123,
              name: "package3",
              dependency: "package3",
              title: "title",
              url: "https://url",
              severity: "moderate",
              range: ">2.1.1 <5.0.1",
            },
          ],
          effects: ["package3"],
          range: ">2.1.1 <5.0.1",
          nodes: ["node_modules/package1/node_modules/package3"],
          fixAvailable: false,
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        advisoriesFound: [123],
      })
    );
  });

  it("should handle undefined `via`", () => {
    const model = new Model({
      levels: { moderate: true },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      vulnerabilities: {
        package1: {
          name: "package1",
          severity: "moderate",
          via: ["package2", "package3"],
          effects: ["package2"],
          range: ">=3.0.1",
          nodes: ["node_modules/package1"],
          fixAvailable: {
            name: "package2",
            version: "3.0.1",
            isSemVerMajor: true,
          },
        },
        package2: {
          name: "package2",
          severity: "moderate",
          via: [],
          effects: ["package1"],
          range: ">=3.0.2",
          nodes: ["node_modules/package2"],
          fixAvailable: {
            name: "package2",
            version: "3.0.1",
            isSemVerMajor: true,
          },
        },
        package3: {
          name: "package3",
          severity: "moderate",
          via: [
            {
              source: 123,
              name: "package3",
              dependency: "package3",
              title: "title",
              url: "https://url",
              severity: "moderate",
              range: ">2.1.1 <5.0.1",
            },
          ],
          effects: ["package3"],
          range: ">2.1.1 <5.0.1",
          nodes: ["node_modules/package1/node_modules/package3"],
          fixAvailable: false,
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        advisoriesFound: [123],
      })
    );
  });
});
