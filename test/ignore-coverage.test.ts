import { describe, it, expect } from "vitest";
import { auditIgnoreCoverage } from "../src/analyzers/ignore-coverage.js";

const issues = (path: string, content: string) =>
  auditIgnoreCoverage(path, content).map((i) => i.issue);

describe("auditIgnoreCoverage — true positives (gaps)", () => {
  it("emits ONE consolidated finding naming a bare-.env gap (the flagship)", () => {
    const r = auditIgnoreCoverage(".cursorignore", "**/.env.*\n");
    expect(r).toHaveLength(1);
    expect(r[0].issue).toBe("ignore-coverage-gap");
    expect(r[0].severity).toBe("warning");
    expect(r[0].description).toMatch(/bare \.env/);
    expect(r[0].suggestion).toContain("**/.env");
  });

  it("lists the common secret shapes missed by a secret/ only ignore in one finding", () => {
    const r = auditIgnoreCoverage(".claudeignore", "**/secret/**\n**/secrets/**\n");
    expect(r).toHaveLength(1);
    for (const p of ["**/.env", "**/*.pem", "**/*.key", "**/*credential*"]) {
      expect(r[0].suggestion).toContain(p);
    }
  });
});

describe("auditIgnoreCoverage — false-positive guards", () => {
  it("is silent for a complete AI-ignore file", () => {
    const complete =
      ".env\n**/.env.*\n**/*.env\n**/id_rsa*\n**/*.pem\n**/*.key\n**/*credential*\n**/.npmrc\n";
    expect(auditIgnoreCoverage(".cursorignore", complete)).toHaveLength(0);
  });

  it("does not audit a file with no secret-protection intent", () => {
    // only build/dep noise -> not trying to protect secrets -> no nagging
    expect(issues(".cursorignore", "node_modules/\ndist/\n.next/\n")).toHaveLength(0);
  });

  it("only audits AI-ignore files — not .gitignore or .vetignore", () => {
    expect(issues(".gitignore", "**/.env.*\n")).toHaveLength(0);
    expect(issues(".vetignore", "**/.env.*\n")).toHaveLength(0);
    expect(issues("src/app.ts", "**/.env.*\n")).toHaveLength(0);
  });

  it("covers nested AI-ignore paths and respects a covering pattern", () => {
    // a bare `.env` pattern covers the .env probe -> no .env gap
    expect(auditIgnoreCoverage("repo/.cursorignore", ".env\n**/*.pem\n").some((i) => i.matchedText === "**/.env")).toBe(
      false
    );
  });
});

describe("auditIgnoreCoverage — boundaries", () => {
  it("empty, comments-only, and malformed content do not crash or flag", () => {
    expect(auditIgnoreCoverage(".cursorignore", "")).toHaveLength(0);
    expect(auditIgnoreCoverage(".cursorignore", "# just a comment\n")).toHaveLength(0);
    expect(() => auditIgnoreCoverage(".cursorignore", "**/[unterminated\n**/.env.*\n")).not.toThrow();
  });
});
