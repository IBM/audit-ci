import { describe, expect, it } from "vitest";
import { runProgram } from "../lib/common.js";

describe("runProgram", () => {
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
    await runProgram(
      process.execPath,
      ["-e", "console.log(JSON.stringify({ ok: true }))"],
      { cwd: process.cwd() },
      () => {
        throw new Error("listener failure");
      },
      (data) => {
        stderr.push(data);
      },
    );
    expect(stderr[0]).toBeInstanceOf(Error);
    expect((stderr[0] as Error).message).toBe("listener failure");
  });
});
