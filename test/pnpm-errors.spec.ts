import { describe, expect, it, vi } from "vitest";
import { runProgram } from "../lib/common.js";
import { auditWithFullConfig } from "../lib/pnpm-auditor.js";
import { config } from "./common.js";

vi.mock("../lib/common.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/common.js")>()),
  runProgram: vi.fn(),
}));

describe("pnpm audit errors", () => {
  it.each([
    { code: "LEGACY", summary: "Legacy error" },
    { code: "ERR_PNPM_AUDIT_NO_LOCKFILE", message: "No lockfile found" },
  ])("preserves the error text for $code", async (error) => {
    vi.mocked(runProgram).mockImplementationOnce(async (_command, _arguments, _options, stdout) => {
      stdout({ error });
    });

    await expect(auditWithFullConfig(config({ "package-manager": "pnpm" }))).rejects.toThrow(
      `code ${error.code}: ${error.summary ?? error.message}`,
    );
  });
});
