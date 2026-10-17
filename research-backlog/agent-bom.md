# Research stub: Agent BOM (AI-agent supply-chain inventory)

> **Status:** PARKED — concept only, not scheduled. Reporting feature (not a gate),
> unproven demand, behind adoption in priority. Internal — do not publish.

## The idea

A dependency **SBOM** (SPDX/CycloneDX) inventories your software's libraries so you
can match them against vuln DBs. That space is commodity and solved (Syft, Grype,
Trivy, OSV-Scanner, Dependabot) — **vet should not rebuild it.**

But almost nobody produces a bill of materials for the **AI-agent supply chain** —
the tools, servers, and context an agent is wired to trust. vet already *detects*
the risky pieces; an **Agent BOM** would *inventory* them as a structured artifact.

## What it would inventory (vet already walks these files)

- **MCP servers** — from `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`,
  `claude_desktop_config.json`: server name, command, source/package, pinned vs
  unpinned, declared tools, `alwaysAllow` grants.
- **Agent configs** — `.claude/settings.json`, `.vscode/settings.json`,
  `.aider.conf.*`, `.continue/config.*`: permission allow/deny lists, autonomy
  flags, hooks.
- **Instruction files** — `CLAUDE.md`, `.cursorrules`, copilot instructions,
  prompt files: present, which tool, size.
- **Agent-reachable external sources** — unpinned `npx -y @vendor/mcp`, `uvx`,
  `curl | sh` in agent-adjacent scripts (supply-chain risk vet already flags).

## Output format

- **CycloneDX** has an ML-BOM / AI transparency extension — the natural target so
  the Agent BOM slots into existing SBOM tooling/dashboards.
- Minimal first cut: a `vet bom --json` subcommand emitting
  `{ mcpServers[], agentConfigs[], instructionFiles[], externalSources[] }`.

## Why it's plausibly in-niche

- Reuses existing detection (MCP scanner, agent scanner, discovery) — small add on
  top of what vet already parses; no new runtime deps, stays local.
- Differentiated — "inventory your agent's tool/context supply chain" is a concept
  nobody owns; pairs with the Zero-Trust-for-agents and "complement to SBOM/SCA"
  positioning.

## Why it's parked (be honest)

- It's a **reporting** feature; vet's value is the **gate** (find-and-fail). An
  inventory is nice-to-have, lower urgency.
- **Demand unproven** — no user has asked for an agent inventory artifact.
- We're in the **adoption** phase; detection/inventory depth is past the frontier
  of diminishing returns until reach improves.

## Open questions (for whenever this thaws)

1. Gate or report? Could `vet bom` also *diff* against a committed baseline and
   fail on new untrusted servers/grants (turning inventory into a gate)?
2. CycloneDX ML-BOM fidelity vs. a simple custom JSON — how much does standard
   format adoption actually buy us?
3. Does this belong in `vet` (CLI artifact) or the VS Code extension (a live
   "agent surface" panel)?

## Decided adjacent (not this doc)

- **Dependency SBOM/SCA:** integrate, don't rebuild — run Syft/Grype/Dependabot
  alongside vet; position vet as the agent-security layer SCA can't see.
