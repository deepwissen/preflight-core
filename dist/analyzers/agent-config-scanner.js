/**
 * Agent-Autonomy Scanner (OWASP LLM06 — Excessive Agency).
 *
 * Detects config/flags that let an AI coding agent act without a human in the
 * loop — run shell, auto-approve tools, bypass permission prompts. Pure pattern/
 * context matching over the active file; no dataflow. See
 * docs/agent-autonomy-scanner.md.
 */
const MAX_FILE_CHARS = 100_000;
const TEST_FILE = /\.(test|spec)\.(ts|tsx|js|jsx)$|__tests__\//;
// Files that carry agent-autonomy config (scope for the generic key rules, so we
// never flag the same word in ordinary source). MCP config files are deliberately
// excluded — their auto-approve grants are owned by the MCP scanner.
const AGENT_CONFIG_PATH = /(^|\/)\.claude\/settings(\.local)?\.json$|(^|\/)\.vscode\/settings\.json$|(^|\/)\.aider\.conf\.ya?ml$|(^|\/)\.continue\/config\.(json|ya?ml)$|(^|\/)\.codex\/config\.(toml|json|ya?ml)$/i;
// Executable contexts where a wired-in bypass flag is a real foot-gun.
const EXEC_CONTEXT_PATH = /(^|\/)package\.json$|(^|\/)Makefile$|\.(sh|bash|zsh)$|(^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(^|\/)\.husky\//i;
const CLAUDE_SETTINGS = /(^|\/)\.claude\/settings(\.local)?\.json$/i;
function lineOf(content, index) {
    return content.slice(0, Math.max(0, index)).split("\n").length;
}
// Generic autonomy flags, matched on raw content (format-agnostic: JSON/YAML/
// TOML). Each fires at most once per file. A value of `false` never matches.
const FLAG_RULES = [
    {
        re: /["']?\b(?:dangerouslySkipPermissions|skipPermissions|bypassPermissions)\b["']?\s*[:=]\s*true\b/i,
        issue: "agent-skip-permissions",
        severity: "error",
        description: "Agent permission prompts are bypassed",
        suggestion: "Require human approval — remove the skip/bypass-permissions flag",
    },
    {
        re: /["']?\byolo(?:[-_]?mode)?\b["']?\s*[:=]\s*true\b/i,
        issue: "agent-skip-permissions",
        severity: "error",
        description: "Agent 'YOLO' mode auto-runs actions without approval",
        suggestion: "Disable YOLO/auto-run mode so changes and commands need confirmation",
    },
    {
        re: /["']?\bdefaultMode\b["']?\s*[:=]\s*["']?bypassPermissions["']?/i,
        issue: "agent-skip-permissions",
        severity: "error",
        description: "Default permission mode is set to bypass approval",
        suggestion: "Set defaultMode to 'ask' (or remove it) so the agent prompts before acting",
    },
    {
        // Aider: auto-confirm every prompt
        re: /["']?\byes-always\b["']?\s*[:=]\s*true\b/i,
        issue: "agent-skip-permissions",
        severity: "error",
        description: "Aider auto-confirms every prompt (yes-always)",
        suggestion: "Set yes-always: false so Aider asks before edits and commands",
    },
    {
        // Codex: full-auto approval
        re: /["']?\bapproval[_-]?mode\b["']?\s*[:=]\s*["']?full-auto["']?/i,
        issue: "agent-skip-permissions",
        severity: "error",
        description: "Approval mode is set to full-auto (no prompts)",
        suggestion: "Use an interactive/suggest approval mode instead of full-auto",
    },
    {
        re: /["']?\b(?:autoApprove|autoApprovalEnabled|alwaysAllowExecute)\b["']?\s*[:=]\s*true\b/i,
        issue: "agent-auto-approve-exec",
        severity: "error",
        description: "Agent auto-approves command execution",
        suggestion: "Turn off auto-approve/always-allow-execute — keep a human in the loop for commands",
    },
    {
        re: /["']?\b(?:alwaysAllowWrite|autoAcceptEdits)\b["']?\s*[:=]\s*true\b/i,
        issue: "agent-auto-approve-write",
        severity: "warning",
        description: "Agent auto-accepts file edits without review",
        suggestion: "Disable auto-accept of edits so changes are reviewed before applying",
    },
    {
        re: /["']?\benableAllProjectMcpServers\b["']?\s*[:=]\s*true\b/i,
        issue: "agent-enable-all-mcp",
        severity: "warning",
        description: "All project MCP servers are enabled automatically",
        suggestion: "Enable MCP servers explicitly rather than all at once",
    },
    {
        re: /"allowedCommands"\s*:\s*\[\s*"\*"\s*\]/,
        issue: "agent-broad-command-allow",
        severity: "error",
        description: "Agent is allowed to run any command (allowedCommands: ['*'])",
        suggestion: "Replace '*' with a scoped allow-list of specific commands",
    },
];
/** Scan the active file for excessive-agency / unsafe-autonomy configuration. */
export function scanAgentConfig(context, _partial) {
    const issues = [];
    const file = context.activeFile;
    if (!file?.content)
        return { instructionFileIssues: issues };
    if (file.content.length > MAX_FILE_CHARS || TEST_FILE.test(file.path)) {
        return { instructionFileIssues: issues };
    }
    const path = file.path;
    const content = file.content;
    const push = (issue, severity, index, description, suggestion) => {
        const line = lineOf(content, index);
        issues.push({
            id: `${issue}-${path}-${line}`,
            filePath: path,
            issue,
            severity,
            lineNumber: line,
            description: `${description} (${path})`,
            suggestion,
        });
    };
    const isAgentConfig = AGENT_CONFIG_PATH.test(path);
    const isExecContext = EXEC_CONTEXT_PATH.test(path);
    // 1. CLI bypass flag wired into an executable context (script/CI/hook) or config.
    if (isExecContext || isAgentConfig) {
        const m = /--(?:dangerously-skip-permissions|full-auto)\b/.exec(content);
        if (m) {
            push("agent-skip-permissions", "error", m.index, `Agent invoked with ${m[0]} (no approval prompts)`, "Drop the auto-approve/skip-permissions flag; let the agent prompt before running tools");
        }
    }
    // 2. Generic autonomy flags — scoped to agent config files to avoid flagging
    //    the same keyword in ordinary source.
    if (isAgentConfig) {
        for (const rule of FLAG_RULES) {
            const m = rule.re.exec(content);
            if (m)
                push(rule.issue, rule.severity, m.index, rule.description, rule.suggestion);
        }
    }
    // 3. Claude Code permissions.allow granting unrestricted shell, and auto-run hooks.
    if (CLAUDE_SETTINGS.test(path)) {
        // Tolerate an unterminated array (truncated/malformed config) by also
        // closing at end-of-content, so a broad allow can't evade via a missing ].
        const allow = /"allow"\s*:\s*\[([\s\S]*?)(?:\]|$)/.exec(content);
        // Only the exact broad tokens — "Bash", "Bash(*)", "*" — not scoped entries
        // like "Bash(git status)" or "Read(*)".
        if (allow && /"(?:Bash(?:\(\*\))?|\*)"/.test(allow[1])) {
            push("agent-broad-command-allow", "error", allow.index, "permissions.allow grants unrestricted shell (Bash(*) / *)", "Scope the allow-list to specific commands instead of a blanket Bash/*");
        }
        const hook = /"(?:PreToolUse|PostToolUse)"\s*:/.exec(content);
        if (hook) {
            push("agent-auto-run-hook", "warning", hook.index, "A hook auto-runs a shell command on tool events", "Confirm the hook command is trusted; it runs automatically without approval");
        }
    }
    // (MCP alwaysAllow/autoApprove is handled by the MCP scanner, not here.)
    return { instructionFileIssues: issues };
}
//# sourceMappingURL=agent-config-scanner.js.map