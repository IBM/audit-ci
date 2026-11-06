import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      thresholds: {
        branches: 84,
        functions: 76,
        lines: 71,
        statements: 72,
      },
    },
    globalSetup: "./test/fixture-setup.ts",
  },
});
