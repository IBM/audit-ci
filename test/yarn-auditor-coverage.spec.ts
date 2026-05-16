import path from "node:path";
import url from "node:url";
import { describe, expect, it, vi } from "vitest";
import { yellow } from "../lib/colors.js";
import * as common from "../lib/common.js";
import Model from "../lib/model.js";
import { auditWithFullConfig, reportBerry, reportClassic } from "../lib/yarn-auditor.js";
import * as yarnVersion from "../lib/yarn-version.js";
import {
  config,
  readYarnBerryAuditOutput,
  readYarnClassicAuditOutput,
  testDirectory,
} from "./common.js";

const yarnClassicPath = path.resolve(
  path.dirname(url.fileURLToPath(import.meta.url)),
  "./yarn-1.22.19.cjs",
);

describe("yarn auditor reporting", () => {
  it("prints classic full and summary output in text mode", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      reportClassic(
        readYarnClassicAuditOutput("yarn-1-high"),
        config({
          directory: testDirectory("yarn-1-high"),
          levels: { high: true },
          "package-manager": "yarn",
          "report-type": "full",
          "output-format": "text",
        }),
        (_summary) => _summary,
      );

      reportClassic(
        readYarnClassicAuditOutput("yarn-1-high"),
        config({
          directory: testDirectory("yarn-1-high"),
          levels: { high: true },
          "package-manager": "yarn",
          "report-type": "summary",
          "output-format": "text",
        }),
        (_summary) => _summary,
      );

      expect(logSpy.mock.calls.length).toBeGreaterThan(0);
    } finally {
      logSpy.mockRestore();
    }
  });

  it("skips yarn headers in json output mode", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      reportClassic(
        readYarnClassicAuditOutput("yarn-1-high"),
        config({
          directory: testDirectory("yarn-1-high"),
          levels: { high: true },
          "package-manager": "yarn",
          "report-type": "important",
          "output-format": "json",
        }),
        (_summary) => _summary,
      );
      expect(logSpy.mock.calls.some((call) => String(call[0]).includes("audit report"))).toBe(
        false,
      );
    } finally {
      logSpy.mockRestore();
    }
  });

  it("prints berry full and metadata output", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      reportBerry(
        readYarnBerryAuditOutput("yarn-2-high"),
        config({
          directory: testDirectory("yarn-2-high"),
          levels: { high: true },
          "package-manager": "yarn",
          "report-type": "full",
          "output-format": "text",
        }),
        (_summary) => _summary,
      );

      reportBerry(
        readYarnBerryAuditOutput("yarn-2-high"),
        config({
          directory: testDirectory("yarn-2-high"),
          levels: { high: true },
          "package-manager": "yarn",
          "report-type": "important",
          "output-format": "json",
        }),
        (_summary) => _summary,
      );

      expect(logSpy).toHaveBeenCalled();
    } finally {
      logSpy.mockRestore();
    }
  });

  it("includes classic audit summaries in important output", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      reportClassic(
        readYarnClassicAuditOutput("yarn-1-moderate"),
        config({
          directory: testDirectory("yarn-1-moderate"),
          levels: { moderate: true },
          "package-manager": "yarn",
          "report-type": "important",
          "output-format": "json",
        }),
        (_summary) => _summary,
      );
      const printed = logSpy.mock.calls.map((call) => String(call[0]));
      expect(printed.some((line) => line.includes("vulnerabilities"))).toBe(true);
    } finally {
      logSpy.mockRestore();
    }
  });
});

describe("yarn auditor runtime", () => {
  it("throws for unsupported yarn versions", async () => {
    const getYarnVersionSpy = vi.spyOn(yarnVersion, "getYarnVersion").mockReturnValue("0.0.0");
    const runProgramSpy = vi.spyOn(common, "runProgram").mockResolvedValue();
    try {
      await expect(
        auditWithFullConfig(
          config({
            directory: testDirectory("yarn-1-low"),
            levels: { low: true },
            "package-manager": "yarn",
            _yarn: yarnClassicPath,
          }),
        ),
      ).rejects.toThrow("not supported");
    } finally {
      getYarnVersionSpy.mockRestore();
      runProgramSpy.mockRestore();
    }
  });

  it("rethrows errors while processing yarn audit output", async () => {
    const processSpy = vi.spyOn(Model.prototype, "process").mockImplementation(() => {
      throw new Error("processing failed");
    });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out(readYarnClassicAuditOutput("yarn-1-low")[0]);
      });
    try {
      await expect(
        auditWithFullConfig(
          config({
            directory: testDirectory("yarn-1-low"),
            levels: { low: true },
            "package-manager": "yarn",
            _yarn: yarnClassicPath,
          }),
        ),
      ).rejects.toThrow("processing failed");
      expect(errorSpy).toHaveBeenCalled();
    } finally {
      processSpy.mockRestore();
      errorSpy.mockRestore();
      runProgramSpy.mockRestore();
    }
  });

  it("uses classic skip-dev arguments when auditing", async () => {
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out(readYarnClassicAuditOutput("yarn-1-none"));
      });
    try {
      await auditWithFullConfig(
        config({
          directory: testDirectory("yarn-1-none"),
          levels: { low: true },
          "package-manager": "yarn",
          "skip-dev": true,
          _yarn: yarnClassicPath,
        }),
      );
      const arguments_ = runProgramSpy.mock.calls[0]?.[1] as string[] | undefined;
      expect(arguments_).toEqual(["audit", "--json", "--groups", "dependencies"]);
    } finally {
      runProgramSpy.mockRestore();
    }
  });

  it("passes registry arguments when yarn supports them", async () => {
    const registrySpy = vi.spyOn(yarnVersion, "yarnAuditSupportsRegistry").mockReturnValue(true);
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out(readYarnClassicAuditOutput("yarn-1-none"));
      });
    try {
      await auditWithFullConfig(
        config({
          directory: testDirectory("yarn-1-none"),
          levels: { low: true },
          "package-manager": "yarn",
          registry: "https://example.com",
          _yarn: yarnClassicPath,
        }),
      );
      const arguments_ = runProgramSpy.mock.calls[0]?.[1] as string[] | undefined;
      expect(arguments_).toContain("--registry");
      expect(arguments_).toContain("https://example.com");
    } finally {
      registrySpy.mockRestore();
      runProgramSpy.mockRestore();
    }
  });

  it("warns about a missing lockfile after a live classic audit", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out({ type: "info", data: "No lockfile found." });
        out(readYarnClassicAuditOutput("yarn-1-none"));
      });
    try {
      await auditWithFullConfig(
        config({
          directory: testDirectory("yarn-1-none"),
          levels: { low: true },
          "package-manager": "yarn",
          _yarn: yarnClassicPath,
        }),
      );
      expect(warnSpy).toHaveBeenCalledWith(
        yellow,
        "No yarn.lock file. This does not affect auditing, but it may be a mistake.",
      );
    } finally {
      warnSpy.mockRestore();
      runProgramSpy.mockRestore();
    }
  });
});
