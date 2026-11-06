import { describe, expect, it, vi } from "vitest";
import Allowlist from "../lib/allowlist.js";
import { partition, reportAudit } from "../lib/common.js";
import type { Summary } from "../lib/model.js";

function summary(overrides: Partial<Summary> = {}): Summary {
  return {
    allowlistedModulesFound: [],
    allowlistedAdvisoriesFound: [],
    allowlistedAdvisoriesNotFound: [],
    allowlistedPathsFound: [],
    allowlistedModulesNotFound: [],
    allowlistedPathsNotFound: [],
    failedLevelsFound: [],
    advisoriesFound: [],
    advisoryPathsFound: [],
    ...overrides,
  };
}

describe("partition", () => {
  it("splits values by predicate result", () => {
    expect(partition([1, 2, 3, 4], (n) => n % 2 === 0)).toEqual({
      truthy: [2, 4],
      falsy: [1, 3],
    });
  });
});

describe("reportAudit", () => {
  it("throws when failed severity levels are present", () => {
    expect(() =>
      reportAudit(
        summary({
          failedLevelsFound: ["high"],
          advisoriesFound: ["GHSA-hrpp-h998-j3pp"],
        }),
        {
          allowlist: new Allowlist(),
          "show-found": false,
          "show-not-found": false,
          "output-format": "json",
        },
      ),
    ).toThrow("Failed security audit due to high vulnerabilities.");
  });

  it("prints allowlist guidance in text mode", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      reportAudit(
        summary({
          allowlistedModulesFound: ["lodash"],
          allowlistedAdvisoriesFound: ["GHSA-rp65-9cf3-cjxr"],
          allowlistedModulesNotFound: ["unused-module"],
          allowlistedAdvisoriesNotFound: ["GHSA-missing"],
          allowlistedPathsNotFound: ["GHSA-path|pkg"],
          advisoryPathsFound: ["GHSA-found|pkg"],
        }),
        {
          allowlist: new Allowlist(["lodash", "GHSA-rp65-9cf3-cjxr"]),
          "show-found": true,
          "show-not-found": true,
          "output-format": "text",
        },
      );
      expect(logSpy).toHaveBeenCalled();
      expect(warnSpy).toHaveBeenCalled();
      const warnMessages = warnSpy.mock.calls.map((call) => String(call[1]));
      expect(
        warnMessages.some((message) => message.includes("Found vulnerable allowlisted modules")),
      ).toBe(true);
      expect(
        warnMessages.some((message) => message.includes("Consider not allowlisting module:")),
      ).toBe(true);
      expect(
        warnMessages.some((message) => message.includes("Consider not allowlisting advisory:")),
      ).toBe(true);
      expect(
        warnMessages.some((message) => message.includes("Consider not allowlisting path:")),
      ).toBe(true);
      expect(
        warnMessages.some((message) => message.includes("Found vulnerable advisory paths")),
      ).toBe(true);
    } finally {
      warnSpy.mockRestore();
      logSpy.mockRestore();
    }
  });

  it("uses plural allowlist guidance when multiple entries are missing", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      reportAudit(
        summary({
          allowlistedModulesNotFound: ["a", "b"],
          allowlistedAdvisoriesNotFound: ["GHSA-38f5-ghc2-fcmv", "GHSA-rp65-9cf3-cjxr"],
          allowlistedPathsNotFound: ["GHSA-38f5-ghc2-fcmv|a", "GHSA-rp65-9cf3-cjxr|b"],
        }),
        {
          allowlist: new Allowlist([]),
          "show-found": false,
          "show-not-found": true,
          "output-format": "text",
        },
      );
      const warnMessages = warnSpy.mock.calls.map((call) => String(call[1]));
      expect(warnMessages.some((message) => message.includes("modules:"))).toBe(true);
      expect(warnMessages.some((message) => message.includes("advisories:"))).toBe(true);
      expect(warnMessages.some((message) => message.includes("paths:"))).toBe(true);
    } finally {
      warnSpy.mockRestore();
    }
  });
});
