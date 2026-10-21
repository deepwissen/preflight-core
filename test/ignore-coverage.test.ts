import { describe, it, expect } from "vitest";
import { auditSecretExposure, auditIgnoreCoverage } from "../src/analyzers/ignore-coverage.js";

// The caveat must be present on EVERY finding — the tool must never grant the
// false confidence that an ignore file protects secrets from the AI.
const CAVEAT = /best-effort|bypass|keep secrets out|rotate|canary/i;

describe("auditSecretExposure — ground truth (primary)", () => {
  it("flags a real secret file not covered by any AI-ignore", () => {
    const r = auditSecretExposure([".pgpass", "config/db.yaml"], [
      { path: ".cursorignore", content: "**/.env.*\n" },
    ]);
    expect(r).toHaveLength(1);
    expect(r[0].issue).toBe("secret-ai-reachable");
    expect(r[0].description).toMatch(/\.pgpass/);
    expect(r[0].suggestion).toMatch(CAVEAT); // caveat, not a pattern
  });

  it("fires loudest on the careless case — secrets present, NO AI-ignore at all", () => {
    const r = auditSecretExposure(["secrets/prod.env"], []);
    expect(r).toHaveLength(1);
    expect(r[0].issue).toBe("secret-ai-reachable");
  });

  it("does not fire for a secret file that IS covered", () => {
    const r = auditSecretExposure([".env"], [{ path: ".cursorignore", content: "**/.env\n" }]);
    expect(r).toHaveLength(0);
  });

  it("no secrets → no finding (never a positive 'protected' verdict)", () => {
    expect(auditSecretExposure([], [{ path: ".cursorignore", content: "**/.env\n" }])).toHaveLength(0);
  });
});

describe("auditIgnoreCoverage — hygiene lint (secondary), always caveated", () => {
  it("flags canon gaps but frames it as hygiene and carries the caveat", () => {
    const r = auditIgnoreCoverage(".cursorignore", "**/.env.*\n");
    expect(r).toHaveLength(1);
    expect(r[0].issue).toBe("ignore-coverage-gap");
    expect(r[0].description).toMatch(/pattern hygiene/i); // not "protected"
    expect(r[0].description).toMatch(/bare \.env/);
    expect(r[0].suggestion).toMatch(/\*\*\/\.env/); // the fix line
    expect(r[0].suggestion).toMatch(CAVEAT); // AND the caveat
  });

  it("is silent on a complete canon and on intent-less files (no positive verdict)", () => {
    const complete = ".env\n**/*.env\n**/id_rsa*\n**/*.pem\n**/*.key\n**/*credential*\n**/.npmrc\n";
    expect(auditIgnoreCoverage(".cursorignore", complete)).toHaveLength(0);
    expect(auditIgnoreCoverage(".cursorignore", "node_modules/\ndist/\n")).toHaveLength(0);
  });

  it("only lints AI-ignore files — never .gitignore/.vetignore/source", () => {
    expect(auditIgnoreCoverage(".gitignore", "**/.env.*\n")).toHaveLength(0);
    expect(auditIgnoreCoverage(".vetignore", "**/.env.*\n")).toHaveLength(0);
    expect(auditIgnoreCoverage("src/app.ts", "**/.env.*\n")).toHaveLength(0);
  });

  it("empty/comments-only/malformed content does not crash or flag", () => {
    expect(auditIgnoreCoverage(".cursorignore", "")).toHaveLength(0);
    expect(auditIgnoreCoverage(".cursorignore", "# comment\n")).toHaveLength(0);
    expect(() => auditIgnoreCoverage(".cursorignore", "**/[bad\n**/.env.*\n")).not.toThrow();
  });
});
