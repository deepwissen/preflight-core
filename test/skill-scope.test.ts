import { describe, it, expect } from "vitest";
import {
  extractSkillScope,
  scanSkillScope,
  isSkillScopeFile,
} from "../src/analyzers/skill-scope.js";

const fm = (body: string) => `---\n${body}\n---\n\nDo the thing.\n`;

describe("isSkillScopeFile", () => {
  it("matches skills, commands, and subagent defs", () => {
    expect(isSkillScopeFile(".claude/skills/pr-review/SKILL.md")).toBe(true);
    expect(isSkillScopeFile("SKILL.md")).toBe(true);
    expect(isSkillScopeFile("plugins/acme/skills/deploy/SKILL.md")).toBe(true);
    expect(isSkillScopeFile(".claude/commands/release.md")).toBe(true);
    expect(isSkillScopeFile(".claude/agents/reviewer.md")).toBe(true);
  });
  it("rejects ordinary markdown", () => {
    expect(isSkillScopeFile("README.md")).toBe(false);
    expect(isSkillScopeFile("docs/myskill.md")).toBe(false);
  });
});

describe("extractSkillScope — parsing", () => {
  it("parses name, description, and scoped tools without flagging broad", () => {
    const s = extractSkillScope(
      ".claude/skills/pr-review/SKILL.md",
      fm("name: pr-review\ndescription: Review a PR\nallowed-tools: Read, Grep, Bash(git diff:*)")
    );
    expect(s.isSkill).toBe(true);
    expect(s.name).toBe("pr-review");
    expect(s.description).toBe("Review a PR");
    expect(s.declaredTools).toBe(true);
    expect(s.tools.map((t) => t.tool)).toEqual(["Read", "Grep", "Bash"]);
    expect(s.tools[2].arg).toBe("git diff:*");
    expect(s.broad).toBe(false);
    expect(s.broadGrants).toEqual([]);
  });

  it("does not split commas inside a grant's parentheses", () => {
    const s = extractSkillScope(
      "SKILL.md",
      fm("allowed-tools: Bash(git log --oneline, --stat), Read")
    );
    expect(s.tools.map((t) => t.raw)).toEqual(["Bash(git log --oneline, --stat)", "Read"]);
  });

  it("parses a YAML block-list form", () => {
    const s = extractSkillScope(
      "SKILL.md",
      fm("name: x\nallowed-tools:\n  - Read\n  - Bash(npm test:*)")
    );
    expect(s.tools.map((t) => t.tool)).toEqual(["Read", "Bash"]);
    expect(s.broad).toBe(false);
  });

  it("marks no-frontmatter and no-allowed-tools as declaredTools:false (not a finding)", () => {
    const noFm = extractSkillScope("SKILL.md", "Just prose, no frontmatter.\n");
    expect(noFm.isSkill).toBe(true);
    expect(noFm.declaredTools).toBe(false);
    expect(noFm.broad).toBe(false);

    const noTools = extractSkillScope("SKILL.md", fm("name: x\ndescription: y"));
    expect(noTools.declaredTools).toBe(false);
    expect(noTools.broad).toBe(false);
  });

  it("returns isSkill:false for non-skill paths", () => {
    const s = extractSkillScope("README.md", fm("allowed-tools: Bash(*)"));
    expect(s.isSkill).toBe(false);
    expect(s.broad).toBe(false);
  });
});

describe("extractSkillScope — over-broad detection", () => {
  it("flags Bash(*), bare Bash, and * as broad; keeps the offending grants", () => {
    expect(extractSkillScope("SKILL.md", fm("allowed-tools: Read, Bash(*)")).broadGrants).toEqual([
      "Bash(*)",
    ]);
    expect(extractSkillScope("SKILL.md", fm("allowed-tools: Bash")).broad).toBe(true);
    expect(extractSkillScope("SKILL.md", fm("allowed-tools: *")).broad).toBe(true);
    expect(extractSkillScope("SKILL.md", fm("allowed-tools: Bash(:*)")).broad).toBe(true);
  });
});

describe("scanSkillScope — findings", () => {
  it("emits an excessive-agency error for an over-broad skill, at the allowed-tools line", () => {
    const content = fm("name: deployer\nallowed-tools: Bash(*)");
    const issues = scanSkillScope(".claude/skills/deployer/SKILL.md", content);
    expect(issues).toHaveLength(1);
    expect(issues[0].issue).toBe("agent-broad-command-allow");
    expect(issues[0].severity).toBe("error");
    expect(issues[0].matchedText).toBe("Bash(*)");
    // frontmatter: line1 '---', line2 name, line3 allowed-tools
    expect(issues[0].lineNumber).toBe(3);
  });

  it("returns nothing for a scoped skill", () => {
    const issues = scanSkillScope(
      ".claude/skills/pr-review/SKILL.md",
      fm("allowed-tools: Read, Bash(git diff:*)")
    );
    expect(issues).toEqual([]);
  });

  it("returns nothing for a non-skill file", () => {
    expect(scanSkillScope("config.json", fm("allowed-tools: Bash(*)"))).toEqual([]);
  });
});
