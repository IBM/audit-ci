import { describe, expect, it } from "vitest";
import { runProgram } from "../lib/common.js";

describe("runProgram", () => {
  it("normalizes non-Error failures from third-party listeners", async () => {
    await expect(
      runProgram(
        process.execPath,
        ["-e", "console.log('{}')"],
        {},
        () => {
          // oxlint-disable-next-line typescript/only-throw-error -- Exercise malformed third-party callback failures.
          throw "listener failure";
        },
        () => {},
      ),
    ).rejects.toThrow("listener failure");
  });
  it("streams parsed JSON objects to the stdout listener", async () => {
    const received: unknown[] = [];
    await runProgram(
      process.execPath,
      ["-e", "console.log(JSON.stringify({ ok: true }))"],
      { cwd: process.cwd() },
      (data) => {
        received.push(data);
      },
      () => {},
    );
    expect(received).toEqual([{ ok: true }]);
  });

  it("routes ENOTFOUND responses to the stderr listener", async () => {
    const stderr: unknown[] = [];
    await runProgram(
      process.execPath,
      ["-e", 'console.log(JSON.stringify({ message: "ENOTFOUND registry.example" }))'],
      { cwd: process.cwd() },
      () => {
        throw new Error("stdout listener should not be called");
      },
      (data) => {
        stderr.push(data);
      },
    );
    expect(stderr).toEqual(["ENOTFOUND registry.example"]);
  });

  it("routes 404 responses to the stderr listener", async () => {
    const stderr: unknown[] = [];
    await runProgram(
      process.execPath,
      ["-e", 'console.log(JSON.stringify({ statusCode: 404, message: "not found" }))'],
      { cwd: process.cwd() },
      () => {
        throw new Error("stdout listener should not be called");
      },
      (data) => {
        stderr.push(data);
      },
    );
    expect(stderr).toEqual(["not found"]);
  });

  it("routes stdout listener errors to the stderr listener", async () => {
    const stderr: unknown[] = [];
    await expect(
      runProgram(
        process.execPath,
        ["-e", "console.log(JSON.stringify({ ok: true }))"],
        { cwd: process.cwd() },
        () => {
          throw new Error("listener failure");
        },
        (data) => {
          stderr.push(data);
        },
      ),
    ).rejects.toThrow("listener failure");
    expect(stderr[0]).toBeInstanceOf(Error);
    expect((stderr[0] as Error).message).toBe("listener failure");
  });
  it("rejects malformed JSON without throwing an uncaught stream error", async () => {
    await expect(
      runProgram(
        process.execPath,
        ["-e", "console.log('{invalid')"],
        {},
        () => {},
        () => {},
      ),
    ).rejects.toThrow("{invalid");
  });
  it("rejects errors thrown by the stderr listener", async () => {
    await expect(
      runProgram(
        process.execPath,
        ["-e", 'console.log(JSON.stringify({ statusCode: 404, message: "not found" }))'],
        {},
        () => {},
        () => {
          throw new Error("registry failure");
        },
      ),
    ).rejects.toThrow("registry failure");
  });
  it("accepts valid audit output with a nonzero vulnerability exit code", async () => {
    const received: unknown[] = [];
    await runProgram(
      process.execPath,
      ["-e", "console.log(JSON.stringify({ vulnerabilities: {} })); process.exitCode = 1"],
      {},
      (data) => {
        received.push(data);
      },
      () => {},
    );
    expect(received).toEqual([{ vulnerabilities: {} }]);
  });
});
