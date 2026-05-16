import { describe, expect, it } from "vitest";
import { mapArgvToAuditCiConfig } from "../lib/config.js";
import { testDirectory } from "./common.js";

function baseArgv(
  overrides: Partial<Parameters<typeof mapArgvToAuditCiConfig>[0]> = {},
): Parameters<typeof mapArgvToAuditCiConfig>[0] {
  const directory = testDirectory("npm-none");
  return {
    l: false,
    low: false,
    m: false,
    moderate: false,
    h: false,
    high: false,
    c: false,
    critical: false,
    p: "npm",
    "package-manager": "npm",
    r: false,
    report: false,
    s: false,
    summary: false,
    a: [],
    allowlist: [],
    d: directory,
    directory,
    "show-not-found": true,
    "show-found": true,
    o: "text",
    "output-format": "text",
    "report-type": "important",
    "retry-count": 5,
    "pass-enoaudit": false,
    "skip-dev": false,
    "extra-args": [],
    ...overrides,
  };
}

describe("mapArgvToAuditCiConfig", () => {
  it("maps report types from argv", () => {
    expect(mapArgvToAuditCiConfig(baseArgv({ "report-type": "full" }))["report-type"]).toBe("full");
    expect(mapArgvToAuditCiConfig(baseArgv({ "report-type": "summary" }))["report-type"]).toBe(
      "summary",
    );
  });

  it("throws for invalid report types from argv", () => {
    expect(() =>
      mapArgvToAuditCiConfig(
        baseArgv({
          "report-type": "invalid" as Parameters<typeof mapArgvToAuditCiConfig>[0]["report-type"],
        }),
      ),
    ).toThrow("Invalid report type");
  });

  it("unescapes leading backslashes in argv extra-args", () => {
    const config = mapArgvToAuditCiConfig(
      baseArgv({ "extra-args": ["\\--legacy-peer-deps", "--foo"] }),
    );
    expect(config["extra-args"]).toEqual(["--legacy-peer-deps", "--foo"]);
  });

  it("resolves auto package manager from argv", () => {
    const config = mapArgvToAuditCiConfig(
      baseArgv({
        "package-manager": "auto",
        directory: testDirectory("pnpm-critical"),
      }),
    );
    expect(config["package-manager"]).toBe("pnpm");
  });
});
