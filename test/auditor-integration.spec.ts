import path from "node:path";
import url from "node:url";
import { describe, expect, it, vi } from "vitest";
import { yellow } from "../lib/colors.js";
import * as common from "../lib/common.js";
import { mapAuditCiConfigToAuditCiFullConfig } from "../lib/config.js";
import {
  audit as auditNpm,
  auditWithFullConfig as auditWithFullConfigNpm,
} from "../lib/npm-auditor.js";
import {
  audit as auditYarn,
  auditWithFullConfig as auditWithFullConfigYarn,
  reportClassic,
} from "../lib/yarn-auditor.js";
import {
  config,
  readYarnBerryAuditOutput,
  readYarnClassicAuditOutput,
  testDirectory,
} from "./common.js";
import reportNpmNone from "./npm-none/npm-output.json" with { type: "json" };

const yarnBerryPath = path.resolve(
  path.dirname(url.fileURLToPath(import.meta.url)),
  "./yarn-2.4.0.cjs",
);
const yarnClassicPath = path.resolve(
  path.dirname(url.fileURLToPath(import.meta.url)),
  "./yarn-1.22.19.cjs",
);

describe("npm auditor integration", () => {
  it("wraps audit config and surfaces npm error responses", async () => {
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out({ error: { code: 1, summary: "npm audit failed" } });
      });
    try {
      await expect(
        auditWithFullConfigNpm(
          mapAuditCiConfigToAuditCiFullConfig({
            "package-manager": "npm",
            directory: testDirectory("npm-low"),
            low: true,
          }),
        ),
      ).rejects.toThrow("code 1: npm audit failed");
    } finally {
      runProgramSpy.mockRestore();
    }
  });

  it("wraps audit config and surfaces npm message responses", async () => {
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out({ message: "npm audit unavailable" });
      });
    try {
      await expect(
        auditWithFullConfigNpm(
          mapAuditCiConfigToAuditCiFullConfig({
            "package-manager": "npm",
            directory: testDirectory("npm-low"),
            low: true,
          }),
        ),
      ).rejects.toThrow("npm audit unavailable");
    } finally {
      runProgramSpy.mockRestore();
    }
  });

  it("exposes the audit helper", async () => {
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out(reportNpmNone);
      });
    try {
      await auditNpm(
        {
          "package-manager": "npm",
          directory: testDirectory("npm-none"),
          low: true,
        },
        (summary) => summary,
      );
      expect(runProgramSpy).toHaveBeenCalled();
    } finally {
      runProgramSpy.mockRestore();
    }
  });

  it("passes --production when skip-dev is enabled", async () => {
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out(reportNpmNone);
      });
    try {
      await auditWithFullConfigNpm(
        mapAuditCiConfigToAuditCiFullConfig({
          "package-manager": "npm",
          directory: testDirectory("npm-none"),
          low: true,
          "skip-dev": true,
        }),
      );
      const arguments_ = runProgramSpy.mock.calls[0]?.[1] as string[] | undefined;
      expect(arguments_).toContain("--production");
    } finally {
      runProgramSpy.mockRestore();
    }
  });
});

describe("yarn auditor integration", () => {
  it("warns when no lockfile is reported for Yarn Classic output", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      reportClassic(
        [{ type: "info", data: "No lockfile found." }, ...readYarnClassicAuditOutput("yarn-1-low")],
        config({
          directory: testDirectory("yarn-1-low"),
          levels: { low: true },
          "package-manager": "yarn",
        }),
        (summary) => summary,
      );
      expect(warnSpy).toHaveBeenCalledWith(
        yellow,
        "No yarn.lock file. This does not affect auditing, but it may be a mistake.",
      );
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("uses Yarn Berry audit arguments when auditing", async () => {
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out(readYarnBerryAuditOutput("yarn-2-none"));
      });
    try {
      await auditWithFullConfigYarn(
        mapAuditCiConfigToAuditCiFullConfig({
          "package-manager": "yarn",
          directory: testDirectory("yarn-2-none"),
          low: true,
          "skip-dev": true,
          "extra-args": ["--foo"],
          _yarn: yarnBerryPath,
        }),
      );
      const arguments_ = runProgramSpy.mock.calls[0]?.[1] as string[] | undefined;
      expect(arguments_).toEqual([
        "npm",
        "audit",
        "--recursive",
        "--json",
        "--all",
        "--environment",
        "production",
        "--foo",
      ]);
    } finally {
      runProgramSpy.mockRestore();
    }
  });

  it("throws when Yarn writes an error event to stderr", async () => {
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, ____, stderr) => {
        stderr({ type: "error", data: "yarn audit failed" });
      });
    try {
      await expect(
        auditWithFullConfigYarn(
          mapAuditCiConfigToAuditCiFullConfig({
            "package-manager": "yarn",
            directory: testDirectory("yarn-1-low"),
            low: true,
            _yarn: yarnClassicPath,
          }),
        ),
      ).rejects.toThrow("yarn audit failed");
    } finally {
      runProgramSpy.mockRestore();
    }
  });

  it("exposes the audit helper", async () => {
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out(readYarnBerryAuditOutput("yarn-2-none"));
      });
    try {
      await auditYarn(
        {
          "package-manager": "yarn",
          directory: testDirectory("yarn-2-none"),
          low: true,
          _yarn: yarnBerryPath,
        },
        (summary) => summary,
      );
      expect(runProgramSpy).toHaveBeenCalled();
    } finally {
      runProgramSpy.mockRestore();
    }
  });
});
