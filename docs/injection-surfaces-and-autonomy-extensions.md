# Design: Trusted-content injection surfaces (B-narrow) + autonomy key extensions (A1)

**Status:** IMPLEMENTED in core 0.1.5. B-narrow (role-tag spoofing + integrity scan over MCP configs & prompt-typed active file) and A1 (extra autonomy keys) shipped with tests. Decisions taken: prompt globs = extension-typed only (`.prompt`/`.prompty`/`.chatmode.md`/`.github/prompts/`); role-tags = warning; MCP config = whole-file unicode/bidi/role-tag, no phrase-matching; bidi kept at the engine's existing `warning`. The last detection slice before shifting investment to adoption.

## Why

Prompt injection is the #1 OWASP LLM risk (LLM01), and recent lab write-ups
(e.g. Perplexity's "How we engineer safer agents") center two things we can
address *statically*: **untrusted content the agent treats as trusted**, and
**agents with broad privileges**. These two scopes extend capabilities we
already ship — the **instruction-integrity scanner** and the **agent-autonomy
scanner** — rather than opening new axes.

Both are deliberately the **narrow, low-false-positive** halves of larger ideas.
The broad halves (scan *all* prose for injection; model every MCP tool's runtime
capability) are explicitly out of scope — they reintroduce the cry-wolf problem
we spent real effort removing.

---

## B-narrow — widen the trusted-content integrity surface

### Threat
An attacker plants instructions in content the model ingests *as trusted* — not
in an instruction file, but in an MCP tool/prompt **description**, a committed
system-prompt/template, or an MCP config field. The model obeys it ("tool
poisoning" / "line jumping"). Hidden-unicode and bidi tricks hide the payload
from human review.

### Honest static limitation
True MCP **tool-description poisoning** is partly a **runtime** concern: a client
receives tool descriptions when it *connects* to the server, so the text isn't
in a consuming repo's `.mcp.json`. Static scope therefore covers only what's
actually in the repo:
- repos that **define** MCP tools/prompts (server implementations, tool
  manifests) — the descriptions are in source;
- **committed prompt/template** files an agent ingests;
- **MCP config** files themselves (poisoned `description`/name/env fields,
  hidden unicode).
Runtime-served descriptions remain the job of a runtime monitor — out of our
static niche (same reasoning as SQLi).

### What it does
Reuse the integrity detectors (which already power instruction-file scanning)
and apply them to a wider set of **agent-trusted text surfaces**, plus add one
new high-confidence detector:

- **Surfaces (new):** MCP config files (`.mcp.json`, `.vscode/mcp.json`,
  `.cursor/mcp.json`, `claude_desktop_config.json`); committed prompt/template
  files (`**/*.prompt`, `**/prompts/**`, `**/*.chatmode.md`); and — where a repo
  defines an MCP server — tool/prompt `description` string literals.
- **Detectors:**
  - `hidden-unicode` · **warning** · zero-width / invisible chars in a trusted
    surface. *Near-zero FP* — these don't belong in config/prompts.
  - `bidi-override` · **warning** · Unicode bidi control chars (Trojan-Source
    class). *Near-zero FP.* (Matches the engine's existing bidi severity across
    all surfaces; gate with `--fail-on warning` to block. Not escalated to error
    here to avoid a surprising cross-surface behavior change.)
  - `role-tag-spoofing` · **warning** · *(new rule)* — LLM role/turn delimiters
    embedded in content that isn't a chat transcript: `<|im_start|>`,
    `<|system|>`, `[INST]`, `<<SYS>>`. *Low FP* when restricted to these
    LLM-specific tokens.
  - `suspicious-instruction` · **warning** · the existing conservative
    injection-phrase heuristic, applied to the new surfaces unchanged.

### False-positive guards
- Restrict `role-tag-spoofing` to the LLM-specific delimiters above. **Do NOT**
  flag bare `<system>` / `### System:` (common in HTML/markdown) — too noisy.
- Keep `suspicious-instruction` exactly as conservative as it is today; do not
  broaden the phrase list for the new surfaces.
- Respect `.vetignore` + skip test fixtures (engine behavior).
- Do not scan arbitrary docs/READMEs for injection phrases — that is **B-broad**,
  and it is out of scope.

---

## A1 — a handful more autonomy keys/flags

Extend the agent-autonomy scanner's `FLAG_RULES` (same shape as the Aider/Codex
additions) with well-attested, high-signal keys we don't yet catch. These are
the *cheap* half; the fuzzy "classify each tool's network/exec capability" half
(A2) is out of scope.

| Signal | Rule / severity | Notes |
|---|---|---|
| `autoRun: true`, `autoExecute: true` | `agent-auto-approve-exec` · error | generic auto-run of commands |
| `requireApproval: false`, `confirmBeforeRun: false` | `agent-skip-permissions` · error | approval explicitly disabled |
| Claude `defaultMode: "acceptEdits"` | `agent-auto-approve-write` · warning | auto-accepts edits (not exec) |
| Codex `approval_mode: "never"` | `agent-skip-permissions` · error | besides the existing `full-auto` |
| snake_case variants (`auto_approve`, `always_allow_execute`) | map to existing rules | tolerate TOML/YAML styles |

### False-positive guards
- Only fire on the enabling value (`: true` / `: "never"` / `: "acceptEdits"`);
  `false` and safe modes never flag.
- Keep rules scoped to `AGENT_CONFIG_PATH` files (never ordinary source).
- **Verify each key against current tool docs at implementation time** — agent
  config keys drift between versions; a wrong key name is dead weight, a
  too-generic one is an FP. When unsure, omit.

---

## Engine & CLI wiring
- **B-narrow** extends the **integrity scanner** (`scanInstructionIntegrity`):
  run its detectors over the new surfaces, add the `role-tag-spoofing` issue id
  to the `InstructionFileIssue` union. Surfaces reach it via existing snapshot
  slots where possible (`mcpConfigFiles`) plus a prompt-file set; in `vet` (which
  scans per-file) route prompt/MCP files through integrity detection.
- **A1** extends the **agent-autonomy scanner** `FLAG_RULES` — no new issue ids,
  no new category.
- vet categories unchanged: integrity findings → `[integrity]`, autonomy →
  `[agent]`. Severity flows through `--fail-on` as today.

## Mandatory tests (QE)
- **B true positives:** bidi char in an MCP config → `bidi-override` error;
  zero-width char in a `.prompt` file → `hidden-unicode`; `<|im_start|>` in a
  committed prompt → `role-tag-spoofing`.
- **B false-positive guards:** bare `<system>` in a README → **no**
  `role-tag-spoofing`; an ordinary MCP config / prompt with no payload → clean;
  injection-phrase logic unchanged on existing instruction-file tests.
- **A1 true positives:** each new key fires its rule (`autoRun`,
  `requireApproval: false`, `defaultMode: acceptEdits`, `approval_mode: never`).
- **A1 guards:** `false`/safe values → none; keys in `src/*.ts` → none.
- **Regression:** no change to existing integrity / agent-scanner suites.

## Effort & phasing
- **A1** — ~1–2 hours (rules + tests), core patch bump.
- **B-narrow** — ~1 day: wire integrity detectors to MCP-config + prompt-file
  surfaces, add `role-tag-spoofing`, tests. Bundle with A1 in one core bump.
- Propagation: `vet` consumers get both via the `^0.1.x` range; the extension
  needs a rebuild/republish to bundle the new rules.

## Out of scope (deliberately)
- **B-broad:** injection-phrase scanning of all prose/docs — FP swamp.
- **A2:** per-tool network/exec capability classification — needs a maintained
  capability registry; FP + maintenance cost.
- **Runtime defenses** (sandboxes, live content classifiers, endpoint behavioral
  monitoring, read-then-exfiltrate sequence detection) — a different layer; our
  static checks are the complement, not a replacement.

## Open decisions
1. **Prompt-file globs** — which to treat as agent-trusted surfaces: `**/*.prompt`,
   `**/prompts/**`, `**/*.chatmode.md`? (Start conservative; widen on demand.)
2. **`role-tag-spoofing` severity** — warning (recommended) vs error. Bidi stays
   error (Trojan-Source); role tags are lower-certainty → warning.
3. **MCP-config integrity scope** — scan whole-file for hidden-unicode/bidi
   (recommended, near-zero FP) vs only specific fields.
