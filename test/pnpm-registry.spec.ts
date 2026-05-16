import { vi } from "vitest";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execSync: (
      command: Parameters<typeof actual.execSync>[0],
      options?: Parameters<typeof actual.execSync>[1],
    ) => {
      if (String(command).includes("pnpm -v")) {
        return "1.0.0";
      }
      return actual.execSync(command, options);
    },
  };
});

import { describe, expect, it } from "vitest";
import * as common from "../lib/common.js";
import { yellow } from "../lib/colors.js";
import { auditWithFullConfig } from "../lib/pnpm-auditor.js";
import reportPnpmNone from "./pnpm-none/pnpm-output.json" with { type: "json" };
import { mapAuditCiConfigToAuditCiFullConfig } from "../lib/config.js";
import { testDirectory } from "./common.js";

describe("pnpm registry support", () => {
  it("warns when registry is unsupported for the installed pnpm version", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const runProgramSpy = vi
      .spyOn(common, "runProgram")
      .mockImplementation(async (_, __, ___, out) => {
        out(reportPnpmNone);
      });
    try {
      await auditWithFullConfig(
        mapAuditCiConfigToAuditCiFullConfig({
          "package-manager": "pnpm",
          directory: testDirectory("pnpm-low"),
          low: true,
          registry: "https://example.com",
        }),
      );
      expect(warnSpy).toHaveBeenCalledWith(
        yellow,
        "Update PNPM to version >=5.4.0 to use the --registry flag",
      );
      const arguments_ = runProgramSpy.mock.calls[0]?.[1] as string[] | undefined;
      expect(arguments_).not.toContain("--registry");
    } finally {
      warnSpy.mockRestore();
      runProgramSpy.mockRestore();
    }
  });
});
