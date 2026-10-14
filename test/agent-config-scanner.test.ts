import { describe, it, expect } from "vitest";
import { scanAgentConfig } from "../src/analyzers/agent-config-scanner.js";
import type { ContextSnapshot, FileInfo, InstructionFileIssue } from "../src/types.js";

function snapshot(path: string, content: string): ContextSnapshot {
  const activeFile: FileInfo = {
    path,
    languageId: "json",
    lineCount: content.split("\n").length,
    charCount: content.length,
    isActive: true,
    isDirty: false,
    commentLineCount: 0,
    hasConflictMarkers: false,
    content,
  };
  return {
    timestamp: 0,
    activeFile,
    selection: null,
    openTabs: [],
    aiInstructionFiles: [],
    mcpConfigFiles: [],
    toolProfile: null,
    ignoreFiles: [],
    referencedFiles: [],
    terminalContent: null,
    clipboardSize: null,
    chatHistoryLength: 0,
  };
}

const scan = (path: string, content: string): InstructionFileIssue[] =>
  scanAgentConfig(snapshot(path, content), {}).instructionFileIssues ?? [];
const ids = (path: string, content: string) => scan(path, content).map((i) => i.issue);

describe("agent-config-scanner — true positives", () => {
  it("flags Claude broad command allow (Bash(*))", () => {
    const c = `{ "permissions": { "allow": ["Read(*)", "Bash(*)"] } }`;
    const f = scan(".claude/settings.json", c);
    expect(f.map((i) => i.issue)).toContain("agent-broad-command-allow");
    expect(f.find((i) => i.issue === "agent-broad-command-allow")?.severity).toBe("error");
  });

  it("flags bare Bash and lone * in the allow list", () => {
    expect(ids(".claude/settings.json", `{"permissions":{"allow":["Bash"]}}`)).toContain(
      "agent-broad-command-allow"
    );
    expect(ids(".claude/settings.json", `{"permissions":{"allow":["*"]}}`)).toContain(
      "agent-broad-command-allow"
    );
  });

  it("flags defaultMode bypassPermissions", () => {
    expect(ids(".claude/settings.json", `{"permissions":{"defaultMode":"bypassPermissions"}}`)).toContain(
      "agent-skip-permissions"
    );
  });

  it("flags --dangerously-skip-permissions wired into package.json scripts", () => {
    const pkg = `{ "scripts": { "ai": "claude --dangerously-skip-permissions" } }`;
    expect(ids("package.json", pkg)).toContain("agent-skip-permissions");
  });

  it("flags the same flag in a shell script and a CI workflow", () => {
    expect(ids("scripts/run.sh", "claude --dangerously-skip-permissions\n")).toContain(
      "agent-skip-permissions"
    );
    expect(ids(".github/workflows/ci.yml", "run: claude --dangerously-skip-permissions")).toContain(
      "agent-skip-permissions"
    );
  });

  it("flags auto-approve-exec flags and a PreToolUse hook", () => {
    expect(ids(".vscode/settings.json", `{"roo-cline.alwaysAllowExecute": true}`)).toContain(
      "agent-auto-approve-exec"
    );
    expect(ids(".claude/settings.json", `{"hooks":{"PreToolUse":[{"command":"echo hi"}]}}`)).toContain(
      "agent-auto-run-hook"
    );
  });

  it("flags Aider yes-always and Codex full-auto (approval mode + CLI)", () => {
    expect(ids(".aider.conf.yml", `yes-always: true\n`)).toContain("agent-skip-permissions");
    expect(ids(".codex/config.toml", `approval_mode = "full-auto"\n`)).toContain(
      "agent-skip-permissions"
    );
    expect(ids("package.json", `{ "scripts": { "ai": "codex --full-auto" } }`)).toContain(
      "agent-skip-permissions"
    );
  });

  it("flags the A1 key set (requireApproval:false, Codex never, acceptEdits, snake_case)", () => {
    expect(ids(".vscode/settings.json", `{ "requireApproval": false }`)).toContain(
      "agent-skip-permissions"
    );
    expect(ids(".codex/config.toml", `approval_mode = "never"\n`)).toContain("agent-skip-permissions");
    expect(ids(".claude/settings.json", `{ "permissions": { "defaultMode": "acceptEdits" } }`)).toContain(
      "agent-auto-approve-write"
    );
    expect(ids(".continue/config.json", `{ "auto_approve": true }`)).toContain(
      "agent-auto-approve-exec"
    );
  });

  it("flags yolo mode and generic autoApprove", () => {
    expect(ids(".continue/config.json", `{"yolo": true}`)).toContain("agent-skip-permissions");
    expect(ids(".continue/config.json", `{"autoApprove": true}`)).toContain(
      "agent-auto-approve-exec"
    );
  });

  // Note: MCP alwaysAllow/autoApprove is owned by the MCP scanner
  // (scanMcpConfigs, rule mcp-risky-config), not this analyzer.

  it("flags enableAllProjectMcpServers as a warning", () => {
    const f = scan(".claude/settings.json", `{"enableAllProjectMcpServers": true}`);
    expect(f.find((i) => i.issue === "agent-enable-all-mcp")?.severity).toBe("warning");
  });
});

describe("agent-config-scanner — false-positive guards", () => {
  it("does NOT flag scoped allow entries", () => {
    const c = `{ "permissions": { "allow": ["Read(*)", "Bash(git status)", "Bash(npm run test:*)", "Edit(src/**)"] } }`;
    expect(ids(".claude/settings.json", c)).not.toContain("agent-broad-command-allow");
  });

  it("does NOT flag flags explicitly set to false", () => {
    expect(ids(".vscode/settings.json", `{"cline.autoApprovalEnabled": false}`)).toHaveLength(0);
    expect(ids(".continue/config.json", `{"yolo": false}`)).toHaveLength(0);
  });

  it("does NOT flag the keyword in ordinary source files", () => {
    // same words, but not an agent config path -> generic rules don't apply
    expect(ids("src/app.ts", `const autoApprove = true; // business logic`)).toHaveLength(0);
  });

  it("does NOT run generic flag rules on MCP files (owned by the MCP scanner)", () => {
    // .mcp.json is not an agent-config path, so no agent-* duplicate of the MCP scanner
    expect(ids(".mcp.json", `{ "autoApprove": true }`)).toHaveLength(0);
    expect(ids("claude_desktop_config.json", `{ "autoApprove": true }`)).toHaveLength(0);
  });

  it("yes-always: false is not flagged", () => {
    expect(ids(".aider.conf.yml", `yes-always: false\n`)).toHaveLength(0);
  });

  it("treats --dangerously-skip-permissions in docs as non-executable (no finding)", () => {
    expect(ids("README.md", "Run `claude --dangerously-skip-permissions` to skip prompts.")).toHaveLength(
      0
    );
  });

  it("does NOT flag an empty or benign allow list", () => {
    expect(ids(".claude/settings.json", `{"permissions":{"allow":[]}}`)).not.toContain(
      "agent-broad-command-allow"
    );
    expect(ids(".claude/settings.json", `{"permissions":{"deny":["Bash(*)"]}}`)).toHaveLength(0);
  });

});

describe("agent-config-scanner — boundaries", () => {
  it("no active file → no findings", () => {
    const snap = snapshot(".claude/settings.json", "");
    snap.activeFile = null;
    expect(scanAgentConfig(snap, {}).instructionFileIssues).toHaveLength(0);
  });

  it("tolerates malformed JSON without throwing", () => {
    expect(() => scan(".claude/settings.json", `{"permissions": { "allow": ["Bash(*)" `)).not.toThrow();
    expect(ids(".claude/settings.json", `{"permissions": { "allow": ["Bash(*)" `)).toContain(
      "agent-broad-command-allow"
    );
  });

  it("skips test-fixture files", () => {
    expect(ids("test/fixtures/settings.test.json", `{"yolo": true}`)).toHaveLength(0);
  });

  it("reports a line number", () => {
    const c = `{\n  "permissions": {\n    "allow": ["Bash(*)"]\n  }\n}`;
    const hit = scan(".claude/settings.json", c).find((i) => i.issue === "agent-broad-command-allow");
    expect(hit?.lineNumber).toBe(3);
  });
});
