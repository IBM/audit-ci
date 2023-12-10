import { NPMAuditReportV2 } from "audit-types";
import { describe, expect, it } from "vitest";
import Allowlist from "../lib/allowlist.js";
import Model from "../lib/model.js";
import { summaryWithDefault } from "./common.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- Intentionally any to pass bad values
function config(additions: any) {
  return { ...additions };
}

describe("Model", () => {
  it("does not support number parameters for Allowlist", () => {
    expect(
      () =>
        new Model({
          // @ts-expect-error -- testing invalid input
          allowlist: new Allowlist([123]),
          levels: {
            low: true,
            moderate: true,
            high: true,
            critical: true,
          },
        }),
    ).to.throw(
      "Unsupported number as allowlist. Perform codemod to update config to use GitHub advisory as identifiers: https://github.com/quinnturner/audit-ci-codemod with `npx @quinnturner/audit-ci-codemod`. See also: https://github.com/IBM/audit-ci/pull/217",
    );
  });

  it("rejects misspelled severity levels", () => {
    expect(() => new Model(config({ levels: { critical_: true } }))).to.throw(
      "Unsupported severity levels found: critical_",
    );
    expect(
      () =>
        new Model(config({ levels: { Low: true, hgih: true, mdrate: true } })),
    ).to.throw("Unsupported severity levels found: Low, hgih, mdrate");
    expect(
      () =>
        new Model(
          config({
            levels: { mdrate: true, critical: true, hgih: true, low: true },
          }),
        ),
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
      levels: { low: true, high: true, moderate: true, critical: true },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      advisories: {
        1_066_786: {
          id: 1_066_786,
          title: "Command Injection",
          module_name: "open",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-28xh-wpgr-7fm8",
          findings: [{ paths: ["open"] }],
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical"],
        advisoriesFound: ["GHSA-28xh-wpgr-7fm8"],
        advisoryPathsFound: ["GHSA-28xh-wpgr-7fm8|open"],
      }),
    );
  });

  it("ignores severities that are set to false", () => {
    const model = new Model({
      levels: { critical: true, low: true, high: false, moderate: false },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      advisories: {
        "GHSA-a-a-a": {
          id: 1,
          module_name: "M_A",
          github_advisory_id: "GHSA-a-a-a",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-a-a-a",
          findings: [{ paths: ["M_A"] }],
        },
        "GHSA-a-a-b": {
          id: 2,
          module_name: "M_B",
          github_advisory_id: "GHSA-a-a-b",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-b",
          findings: [{ paths: ["M_B"] }],
        },
        "GHSA-a-a-c": {
          id: 3,
          module_name: "M_C",
          github_advisory_id: "GHSA-a-a-c",
          severity: "moderate",
          url: "https://github.com/advisories/GHSA-a-a-c",
          findings: [{ paths: ["M_C"] }],
        },
        "GHSA-a-a-d": {
          id: 4,
          module_name: "M_D",
          github_advisory_id: "GHSA-a-a-d",
          severity: "high",
          url: "https://github.com/advisories/GHSA-a-a-d",
          findings: [{ paths: ["M_D"] }],
        },
        "GHSA-a-a-e": {
          id: 5,
          module_name: "M_E",
          github_advisory_id: "GHSA-a-a-e",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-a-a-e",
          findings: [{ paths: ["M_E"] }],
        },
        "GHSA-a-a-f": {
          id: 6,
          module_name: "M_F",
          github_advisory_id: "GHSA-a-a-f",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-f",
          findings: [{ paths: ["M_F"] }],
        },
        "GHSA-a-a-g": {
          id: 7,
          module_name: "M_G",
          github_advisory_id: "GHSA-a-a-g",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-g",
          findings: [{ paths: ["M_G"] }],
        },
      },
    } satisfies Parameters<typeof model.load>[0];

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical", "low"],
        advisoriesFound: [
          "GHSA-a-a-a",
          "GHSA-a-a-b",
          "GHSA-a-a-e",
          "GHSA-a-a-f",
          "GHSA-a-a-g",
        ],
        advisoryPathsFound: [
          "GHSA-a-a-a|M_A",
          "GHSA-a-a-b|M_B",
          "GHSA-a-a-e|M_E",
          "GHSA-a-a-f|M_F",
          "GHSA-a-a-g|M_G",
        ],
      }),
    );
  });

  it("ignores allowlisted modules", () => {
    const model = new Model({
      levels: { critical: true, low: true, high: true, moderate: true },
      allowlist: new Allowlist(["M_A", "M_D"]),
    });

    const parsedAuditOutput = {
      advisories: {
        "GHSA-a-a-a": {
          id: 1,
          module_name: "M_A",
          github_advisory_id: "GHSA-a-a-a",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-a-a-a",
          findings: [{ paths: ["M_A"] }],
        },
        "GHSA-a-a-b": {
          id: 2,
          module_name: "M_B",
          github_advisory_id: "GHSA-a-a-b",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-b",
          findings: [{ paths: ["M_B"] }],
        },
        "GHSA-a-a-c": {
          id: 3,
          module_name: "M_C",
          github_advisory_id: "GHSA-a-a-c",
          severity: "moderate",
          url: "https://github.com/advisories/GHSA-a-a-c",
          findings: [{ paths: ["M_C"] }],
        },
        "GHSA-a-a-d": {
          id: 4,
          module_name: "M_D",
          github_advisory_id: "GHSA-a-a-d",
          severity: "high",
          url: "https://github.com/advisories/GHSA-a-a-d",
          findings: [{ paths: ["M_D"] }],
        },
        "GHSA-a-a-e": {
          id: 5,
          module_name: "M_E",
          github_advisory_id: "GHSA-a-a-e",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-a-a-e",
          findings: [{ paths: ["M_E"] }],
        },
        "GHSA-a-a-f": {
          id: 6,
          module_name: "M_F",
          github_advisory_id: "GHSA-a-a-f",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-f",
          findings: [{ paths: ["M_F"] }],
        },
        "GHSA-a-a-g": {
          id: 7,
          module_name: "M_G",
          github_advisory_id: "GHSA-a-a-g",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-g",
          findings: [{ paths: ["M_G"] }],
        },
      },
    } satisfies Parameters<typeof model.load>[0];

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedModulesFound: ["M_A", "M_D"],
        failedLevelsFound: ["critical", "low", "moderate"],
        advisoriesFound: [
          "GHSA-a-a-b",
          "GHSA-a-a-c",
          "GHSA-a-a-e",
          "GHSA-a-a-f",
          "GHSA-a-a-g",
        ],
        advisoryPathsFound: [
          "GHSA-a-a-b|M_B",
          "GHSA-a-a-c|M_C",
          "GHSA-a-a-e|M_E",
          "GHSA-a-a-f|M_F",
          "GHSA-a-a-g|M_G",
        ],
      }),
    );
  });

  it("ignores allowlisted advisory IDs", () => {
    const model = new Model({
      levels: { critical: true, low: true, high: true, moderate: true },
      allowlist: new Allowlist(["GHSA-a-a-b", "GHSA-a-a-c", "GHSA-a-a-f"]),
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: "A",
          module_name: "M_A",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-a-a-a",
          findings: [{ paths: ["M_A"] }],
        },
        2: {
          id: 2,
          title: "B",
          module_name: "M_B",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-b",
          findings: [{ paths: ["M_B"] }],
        },
        3: {
          id: 3,
          title: "C",
          module_name: "M_C",
          severity: "moderate",
          url: "https://github.com/advisories/GHSA-a-a-c",
          findings: [{ paths: ["M_C"] }],
        },
        4: {
          id: 4,
          title: "D",
          module_name: "M_D",
          severity: "high",
          url: "https://github.com/advisories/GHSA-a-a-d",
          findings: [{ paths: ["M_D"] }],
        },
        5: {
          id: 5,
          title: "E",
          module_name: "M_E",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-a-a-e",
          findings: [{ paths: ["M_E"] }],
        },
        6: {
          id: 6,
          title: "F",
          module_name: "M_F",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-f",
          findings: [{ paths: ["M_F_1"] }],
        },
        7: {
          id: 6,
          title: "F",
          module_name: "M_F",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-f",
          findings: [{ paths: ["M_F_2"] }],
        },
        8: {
          id: 7,
          title: "G",
          module_name: "M_G",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-g",
          findings: [{ paths: ["M_G"] }],
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        allowlistedAdvisoriesFound: ["GHSA-a-a-b", "GHSA-a-a-c", "GHSA-a-a-f"],
        failedLevelsFound: ["critical", "high", "low"],
        advisoriesFound: [
          "GHSA-a-a-a",
          "GHSA-a-a-d",
          "GHSA-a-a-e",
          "GHSA-a-a-g",
        ],
        advisoryPathsFound: [
          "GHSA-a-a-a|M_A",
          "GHSA-a-a-d|M_D",
          "GHSA-a-a-e|M_E",
          "GHSA-a-a-g|M_G",
        ],
      }),
    );
  });

  it("sorts the failedLevelsFound field", () => {
    const model = new Model({
      levels: { low: true, high: true, moderate: true, critical: true },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      advisories: {
        1: {
          id: 1,
          title: "A",
          module_name: "M_A",
          severity: "low",
          url: "https://github.com/advisories/GHSA-a-a-a",
          findings: [{ paths: ["M_A"] }],
        },
        2: {
          id: 2,
          title: "B",
          module_name: "M_B",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-a-a-b",
          findings: [{ paths: ["M_B_1"] }],
        },
        3: {
          id: 2,
          title: "B",
          module_name: "M_B",
          severity: "critical",
          url: "https://github.com/advisories/GHSA-a-a-b",
          findings: [{ paths: ["M_B_2"] }],
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["critical", "low"],
        advisoriesFound: ["GHSA-a-a-a", "GHSA-a-a-b"],
        advisoryPathsFound: [
          "GHSA-a-a-a|M_A",
          "GHSA-a-a-b|M_B_1",
          "GHSA-a-a-b|M_B_2",
        ],
      }),
    );
  });

  it("should handle advisories that reference each other in a loop for npm 7", () => {
    const model = new Model({
      levels: { low: true, moderate: true, high: false, critical: false },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      vulnerabilities: {
        "GHSA-a-a-a": {
          isDirect: false,
          name: "GHSA-a-a-a",
          severity: "moderate",
          via: ["GHSA-a-a-b", "GHSA-a-a-c"],
          effects: ["GHSA-a-a-b"],
          range: ">=3.0.1",
          nodes: ["node_modules/package1"],
          fixAvailable: {
            name: "GHSA-a-a-b",
            version: "3.0.1",
            isSemVerMajor: true,
          },
        },
        "GHSA-a-a-b": {
          isDirect: false,
          name: "GHSA-a-a-b",
          severity: "moderate",
          via: ["GHSA-a-a-a"],
          effects: ["GHSA-a-a-a"],
          range: ">=3.0.2",
          nodes: ["node_modules/GHSA-a-a-b"],
          fixAvailable: {
            name: "GHSA-a-a-b",
            version: "3.0.1",
            isSemVerMajor: true,
          },
        },
        "GHSA-a-a-c": {
          name: "GHSA-a-a-c",
          isDirect: false,
          via: [
            {
              source: 123,
              name: "GHSA-a-a-c",
              dependency: "GHSA-a-a-c",
              title: "title",
              url: "https://github.com/advisories/GHSA-a-a-c",
              severity: "moderate",
              range: ">2.1.1 <5.0.1",
            },
          ],
          effects: ["GHSA-a-a-c"],
        },
      },
    } satisfies Parameters<typeof model.load>[0];

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-a-a-c"],
        advisoryPathsFound: ["GHSA-a-a-c|GHSA-a-a-c>"],
      }),
    );
  });

  it("should handle undefined `via`", () => {
    const model = new Model({
      levels: { low: true, moderate: true, high: false, critical: false },
      allowlist: new Allowlist(),
    });

    const parsedAuditOutput = {
      vulnerabilities: {
        package1: {
          name: "GHSA-a-a-a",
          severity: "moderate" as const,
          isDirect: false,
          via: ["GHSA-a-a-b", "GHSA-a-a-c"],
          effects: ["GHSA-a-a-b"],
          range: ">=3.0.1",
          nodes: ["node_modules/package1"],
          fixAvailable: {
            name: "GHSA-a-a-b",
            version: "3.0.1",
            isSemVerMajor: true,
          } as NPMAuditReportV2.FixAvailable,
        },
        "GHSA-a-a-b": {
          name: "GHSA-a-a-b",
          severity: "moderate" as const,
          isDirect: true,
          via: [],
          effects: ["GHSA-a-a-a"],
          range: ">=3.0.2",
          nodes: ["node_modules/GHSA-a-a-b"],
          fixAvailable: {
            name: "GHSA-a-a-b",
            version: "3.0.1",
            isSemVerMajor: true,
          } as NPMAuditReportV2.FixAvailable,
        },
        "GHSA-a-a-c": {
          name: "GHSA-a-a-c",
          isDirect: false,
          severity: "moderate" as const,
          via: [
            {
              source: 123,
              name: "GHSA-a-a-c",
              dependency: "GHSA-a-a-c",
              title: "title",
              url: "https://github.com/advisories/GHSA-a-a-c",
              severity: "moderate",
              range: ">2.1.1 <5.0.1",
            },
          ] as NPMAuditReportV2.Via[],
          effects: ["GHSA-a-a-c"],
          range: ">2.1.1 <5.0.1",
          nodes: ["node_modules/GHSA-a-a-a/node_modules/GHSA-a-a-c"],
          fixAvailable: false as const,
        },
      },
    };

    const summary = model.load(parsedAuditOutput);
    expect(summary).to.eql(
      summaryWithDefault({
        failedLevelsFound: ["moderate"],
        advisoriesFound: ["GHSA-a-a-c"],
        advisoryPathsFound: ["GHSA-a-a-c|GHSA-a-a-c>"],
      }),
    );
  });
});
