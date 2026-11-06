import path from "node:path";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { testDirectory } from "./common.js";

const hoisted = vi.hoisted(() => ({
  configFileLoader: undefined as ((configPath: string) => unknown) | undefined,
  argvDirectory: "",
}));

vi.mock("yargs", () => ({
  default: vi.fn(() => {
    const chain = {
      config: vi.fn((_name: string, loader: (configPath: string) => unknown) => {
        hoisted.configFileLoader = loader;
        return chain;
      }),
      options: vi.fn().mockReturnThis(),
      help: vi.fn().mockReturnThis(),
      argv: Promise.resolve({
        l: false,
        low: false,
        m: false,
        moderate: false,
        h: false,
        high: false,
        c: false,
        critical: false,
        p: "auto",
        "package-manager": "auto",
        r: false,
        report: false,
        s: false,
        summary: false,
        a: [],
        allowlist: [],
        d: hoisted.argvDirectory,
        directory: hoisted.argvDirectory,
        "show-not-found": true,
        "show-found": true,
        o: "text",
        "output-format": "text",
        "report-type": "important",
        "retry-count": 5,
        "pass-enoaudit": false,
        "skip-dev": false,
        "extra-args": [],
      }),
    };
    return chain;
  }),
}));

vi.mock("yargs/helpers", () => ({
  hideBin: (arguments_: string[]) => arguments_,
}));

describe("runYargs", () => {
  beforeAll(() => {
    hoisted.argvDirectory = testDirectory("npm-config-file");
  });

  it("maps parsed argv into a full config", async () => {
    const { runYargs } = await import("../lib/config.js");
    const config = await runYargs();
    expect(config["package-manager"]).toBe("npm");
    expect(config.directory).toBe(testDirectory("npm-config-file"));
  });

  it("loads JSONC config files for yargs", () => {
    expect(hoisted.configFileLoader).toBeDefined();
    const parsed = hoisted.configFileLoader!(
      path.join(testDirectory("npm-config-file"), "audit-ci-with-comment.jsonc"),
    );
    expect(parsed).toMatchObject({ allowlist: ["open"] });
  });
});
