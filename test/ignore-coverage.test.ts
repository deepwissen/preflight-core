import { describe, it, expect } from "vitest";
import {
  auditDetectedExposure,
  auditIgnoreCoverage,
  IGNORE_CAVEAT,
  DETECTION_DISCLAIMER,
} from "../src/analyzers/ignore-coverage.js";

// Confidence words must never appear in any output — structurally enforces
// "the tool cannot say you're safe".
const CONFIDENCE_WORDS = /\b(safe|protect(ed|s|ion)?|secure[d]?|complete[d]?|guaranteed?)\b/i;

describe("auditDetectedExposure — detected exposure (primary)", () => {
  it("flags EVERY detected secret as reachable — coverage is not a divider", () => {
    // one file IS covered by the ignore, one isn't — both are reported
    const r = auditDetectedExposure(
      [".env", "config/db.pgpass"],
      [{ path: ".cursorignore", content: "**/.env\n" }]
    );
    expect(r).toHaveLength(1);
    expect(r[0].issue).toBe("secret-ai-reachable");
    expect(r[0].description).toMatch(/\.env/);
    expect(r[0].description).toMatch(/\.pgpass/); // the covered one is STILL reported
    expect(r[0].description).toMatch(/best-effort only, not a barrier/); // coverage = weak note
  });

  it("fires on the careless case — secrets present, no AI-ignore at all", () => {
    expect(auditDetectedExposure(["secrets/prod.env"], [])).toHaveLength(1);
  });

  it("no secrets → no finding (never a 'you're clean' verdict)", () => {
    expect(auditDetectedExposure([], [{ path: ".cursorignore", content: "**/.env\n" }])).toHaveLength(0);
  });
});

describe("mandatory report-level disclaimers", () => {
  it("DETECTION_DISCLAIMER says a clean scan is not proof of no secrets", () => {
    expect(DETECTION_DISCLAIMER).toMatch(/does NOT mean none are present/i);
    expect(DETECTION_DISCLAIMER).not.toMatch(CONFIDENCE_WORDS);
  });

  it("IGNORE_CAVEAT points at the real fix and the canary — once-per-report", () => {
    expect(IGNORE_CAVEAT).toMatch(/best-effort|bypass/i);
    expect(IGNORE_CAVEAT).toMatch(/remove secrets from the working tree/i);
    expect(IGNORE_CAVEAT).toMatch(/canary/i);
    expect(IGNORE_CAVEAT).not.toMatch(CONFIDENCE_WORDS);
  });

  it("findings do NOT each repeat the full caveat (shown once per report instead)", () => {
    const r = auditIgnoreCoverage(".cursorignore", "**/.env.*\n");
    expect(r[0].suggestion).not.toContain(IGNORE_CAVEAT);
    expect(auditDetectedExposure([".env"], [])[0].suggestion).not.toContain(IGNORE_CAVEAT);
  });
});

describe("no output string uses confidence words", () => {
  it("across exposure, lint, and the constants", () => {
    const strings: string[] = [IGNORE_CAVEAT, DETECTION_DISCLAIMER];
    for (const f of auditDetectedExposure([".env", ".pgpass"], [{ path: ".cursorignore", content: "**/.env\n" }])) {
      strings.push(f.description, f.suggestion ?? "");
    }
    for (const f of auditIgnoreCoverage(".cursorignore", "**/.env.*\n")) {
      strings.push(f.description, f.suggestion ?? "");
    }
    for (const s of strings) expect(s).not.toMatch(CONFIDENCE_WORDS);
  });
});

describe("auditIgnoreCoverage — hygiene lint (secondary)", () => {
  it("flags canon gaps, framed as hygiene, with the fix line", () => {
    const r = auditIgnoreCoverage(".cursorignore", "**/.env.*\n");
    expect(r).toHaveLength(1);
    expect(r[0].issue).toBe("ignore-coverage-gap");
    expect(r[0].description).toMatch(/pattern hygiene/i);
    expect(r[0].suggestion).toMatch(/\*\*\/\.env/);
  });

  it("silent on a complete canon and intent-less files; AI-ignore files only", () => {
    const full = ".env\n**/*.env\n**/id_rsa*\n**/*.pem\n**/*.key\n**/*credential*\n**/.npmrc\n";
    expect(auditIgnoreCoverage(".cursorignore", full)).toHaveLength(0);
    expect(auditIgnoreCoverage(".cursorignore", "node_modules/\n")).toHaveLength(0);
    expect(auditIgnoreCoverage(".gitignore", "**/.env.*\n")).toHaveLength(0);
    expect(auditIgnoreCoverage(".vetignore", "**/.env.*\n")).toHaveLength(0);
  });

  it("empty / malformed content does not crash or flag", () => {
    expect(auditIgnoreCoverage(".cursorignore", "")).toHaveLength(0);
    expect(() => auditIgnoreCoverage(".cursorignore", "**/[bad\n**/.env.*\n")).not.toThrow();
  });
});
