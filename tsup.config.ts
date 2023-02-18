import { defineConfig } from "tsup";

export default defineConfig([
  {
    name: "main",
    entry: ["./lib/index.ts"],
    tsconfig: "./tsconfig.build.json",
    outDir: "./dist",
    format: ["esm", "cjs"],
    sourcemap: true,
    clean: true,
    bundle: true,
    dts: true,
  },
]);
