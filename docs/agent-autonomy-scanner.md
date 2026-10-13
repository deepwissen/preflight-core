# Design: Agent-Autonomy Scanner (OWASP LLM06 — Excessive Agency)

**Status:** Phase 1 implemented in `preflight-core` (`src/analyzers/agent-config-scanner.ts`, 19 tests). Decisions taken: **(1)** new `"agent"` category, **(2)** scan executable contexts too, **(3)** bypass/auto-exec = `error`. vet surfacing (the `"agent"` category + `scan.ts` call) lands once core republishes. Phase 2 (Cline/Roo/Aider/Codex/Continue depth) pending.

## Why

Every modern coding agent can be configured to **act without asking** — run
shell, edit files, call network tools, auto-approve MCP tools. That autonomy
lives in config files and CLI flags that no SAST tool inspects and that are
invisible in code review. It is the one OWASP LLM Top-10 category the engine has
**zero** coverage of today, and it is purely config/pattern — a natural fit for
this engine (local, false-positive-first, no dataflow required).

The scanner answers one question per repo:

> **Can an AI agent in this repo run arbitrary commands or make changes without a
> human in the loop?**

### Coverage context (OWASP LLM Top 10, 2025)

| Risk | Engine coverage |
|---|---|
| LLM01 Prompt Injection | partial (instruction files) |
| LLM02 Sensitive Info Disclosure | partial (secrets) |
| LLM03 Supply Chain | partial (MCP unpinned) |
| **LLM06 Excessive Agency** | **none → this scanner** |

## The config surface

Files/keys we parse, per tool. The ruleset is **data-driven** — a table of
`{file-glob, key-path, risky-predicate, ruleId, severity}` — so keeping up with
fast-moving tools is a data edit, not a code change. Keys should be re-verified
against current tool docs at implementation time.

| Tool | File(s) | Risky setting(s) |
|---|---|---|
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json` | `permissions.allow` with `Bash(*)` / bare `Bash` / `*`; `permissions.defaultMode: "bypassPermissions"`; `hooks` (PreToolUse/PostToolUse) running shell |
| Claude Code (CLI) | `package.json` scripts, `Makefile`, `*.sh`, CI yml, `.husky/*` | `--dangerously-skip-permissions` |
| MCP (any) | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` | per-server `alwaysAllow` (esp. `*` or an exec/shell tool); `enableAllProjectMcpServers: true` |
| Cline / Roo | `.vscode/settings.json` (`cline.*` / `roo-cline.*`) | `alwaysAllowExecute: true`, `autoApprovalEnabled: true`, `allowedCommands: ["*"]`, `alwaysAllowWrite`, `alwaysAllowBrowser` |
| Aider | `.aider.conf.yml`, CLI | `yes-always: true` / `--yes-always`; `auto-commits` + `auto-test` running shell |
| Codex CLI | config + CLI | `approvalMode: full-auto` / `--full-auto` / auto-approve-everything |
| Continue | `.continue/config.(json\|yaml)` | per-tool policy set to auto/`allow` for exec tools |
| Cursor / Windsurf | repo-visible bits only (`.cursor/mcp.json`, committed settings) | YOLO / auto-run allowlists when committed |
| Generic | any JSON/YAML/TOML agent config | `yolo(Mode): true`, `autoApprove: true`, `skipPermissions` / `bypassPermissions`, `autoAccept*: true` |

## Detection rules

Format: `ruleId` · severity · trigger · false-positive guard.

### Errors — arbitrary execution without approval
- `agent-skip-permissions` · **error** · `--dangerously-skip-permissions`, `defaultMode: bypassPermissions`, `yolo: true`. *Guard:* executable contexts only — never prose/`.md`.
- `agent-broad-command-allow` · **error** · allow-list grants unrestricted shell: `Bash(*)`, bare `Bash`, `*`, `allowedCommands: ["*"]`. *Guard:* scoped entries (`Bash(git status)`, `Bash(npm run test:*)`, `Read(*)`, `Edit(src/**)`) are safe → never flag.
- `agent-auto-approve-exec` · **error** · `alwaysAllowExecute: true`, Codex `full-auto`, Aider `yes-always: true`.
- MCP auto-approve-all (`alwaysAllow`/`autoApprove` = `*` or `true`) is **owned by the MCP scanner** (`scanMcpConfigs`, rule `mcp-risky-config`, escalated to **error** in 0.1.3) — not duplicated here, to avoid double-reporting the same line.

### Warnings — broad but narrower autonomy
- `agent-auto-approve-write` · **warning** · auto-approve file writes/edits (`alwaysAllowWrite: true`).
- `agent-auto-run-hook` · **warning** · a hook auto-runs shell on tool events (often legit; worth surfacing).
- `agent-enable-all-mcp` · **warning** · `enableAllProjectMcpServers: true` / broad browser/network auto-allow.

### Info / skipped (not security)
`auto-commits`, telemetry, auto-lint → skip (noise).

### Universal false-positive guards
- A flag explicitly `false` (`autoApprove: false`) → never flag.
- `deny` / `ask` lists are protective → never flag (their presence is good).
- Respect `.vetignore` and skip test fixtures (already engine behavior).
- CLI bypass flags only flagged in executable contexts; a mention in README/docs is at most `info`.

## Engine & CLI wiring
- New analyzer `src/analyzers/agent-config-scanner.ts` in `preflight-core`. Parses the agent config files (JSON/YAML/TOML) and walks the rule table. Reuses existing MCP file detection for the `alwaysAllow` rules. Emits the existing `InstructionFileIssue` shape (no new result plumbing) with the new rule IDs.
- New vet category `"agent"` added to `Category` (today `secret | trap | integrity | mcp`). vet `scan.ts` maps `agent-*` rule IDs → `category: "agent"`. (See open decision 1.)
- Severity flows through `--fail-on` exactly as today, so `agent-skip-permissions` blocks a PR under the default `error`.
- Surfaces in the VS Code extension automatically via the shared engine.

## Mandatory tests (QE)
- **True positives** per tool: each risky key/flag fires its rule (Claude `Bash(*)`, `--dangerously-skip-permissions`, Cline `alwaysAllowExecute`, Aider `yes-always`, MCP `alwaysAllow: ["*"]`, generic `yolo: true`).
- **False-positive guards** (the important half): scoped allows (`Bash(git:*)`, `Read(*)`) → no finding; `autoApprove: false` → none; a `deny` list → none; `--dangerously-skip-permissions` documented in `.md` → at most info; a non-agent `.vscode/settings.json` → none.
- **Boundary:** empty config, malformed JSON/YAML (no crash), unknown keys ignored.
- **Severity/contract:** error-rules trip `--fail-on error`; warning-rules do not.
- **Parity:** same corpus clean through `vet` and the extension.

## Effort & phasing
- **Phase 1** — Claude Code (`permissions`, `--dangerously-skip-permissions`) + MCP `alwaysAllow` + generic boolean flags (`yolo` / `autoApprove` / `skipPermissions`). Highest-impact, highest-confidence set. ~1 day incl. tests.
- **Phase 2** — Cline/Roo, Aider, Codex, Continue; CLI-in-scripts/CI detection. ~1 day.
- Patch-bump `preflight-core` → `vet` picks it up via `^0.1.0`; add examples to `COMMANDS.md`.

## Open decisions (gate the build)
1. **Category** — new `"agent"` category (recommended; clean grouping) vs reuse `"mcp"` (zero type churn).
2. **CLI scan** — also scan executable contexts (package.json scripts, Makefile, `*.sh`, CI yml, `.husky`) for bypass flags (recommended; common foot-gun) vs config files only in Phase 1.
3. **Severity** — bypass/auto-exec = `error` (recommended; actually gates) vs all autonomy = `warning` (advisory only).

## Positioning
Complementary, not a replacement for SAST. SAST scans source; this scans whether
the *agent* is over-permissioned — a layer no SAST tool covers. Aggregate
alongside existing scanners via SARIF.
