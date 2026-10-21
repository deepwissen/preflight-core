import { describe, it, expect } from "vitest";
import { auditIgnoreCoverage } from "../src/analyzers/ignore-coverage.js";

const issues = (path: string, content: string) =>
  auditIgnoreCoverage(path, content).map((i) => i.issue);
const suggestions = (path: string, content: string) =>
  auditIgnoreCoverage(path, content).map((i) => i.matchedText);

describe("auditIgnoreCoverage — true positives (gaps)", () => {
  it("flags a bare .env slipping past **/.env.* (the flagship gap)", () => {
    const r = auditIgnoreCoverage(".cursorignore", "**/.env.*\n");
    const envGap = r.find((i) => i.matchedText === "**/.env");
    expect(envGap).toBeDefined();
    expect(envGap?.issue).toBe("ignore-coverage-gap");
    expect(envGap?.severity).toBe("warning");
    expect(envGap?.suggestion).toContain("**/.env");
  });

  it("flags the common secret shapes missed by a secret/ only ignore", () => {
    const sug = suggestions(".claudeignore", "**/secret/**\n**/secrets/**\n");
    expect(sug).toEqual(expect.arrayContaining(["**/.env", "**/*.pem", "**/*.key", "**/*credential*"]));
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
