# Design: AI-ignore coverage audit (`ignore-coverage-gap`)

**Status:** IMPLEMENTED in core 0.1.11 — `auditIgnoreCoverage(path, content)`
(`src/analyzers/ignore-coverage.ts`) + shared gitignore matcher
(`src/ignore-match.ts`), 13 tests. vet/extension wiring lands after core 0.1.11
publishes (they need the new export). Promoted from research-backlog A-Phase-1.

## Why

Teams use `.cursorignore` / `.claudeignore` to keep secret files away from the AI
and treat it as a security control. But the patterns routinely don't cover what
people think. The canonical failure:

```gitignore
# .cursorignore
**/.env.*        # matches .env.local, .env.production …
```

`**/.env.*` does **not** match a bare `.env` — the single most common secret file
sails straight through and remains AI-reachable. Same class: `**/secret/**` only
covers files *inside* a `secret/` directory, missing `credentials.json`, `*.pem`,
`config/secret.yaml`.

Almost no tool audits an AI-ignore file for *completeness*. This detector does —
catching the "it looks protective but isn't" gap.

## Scope (Phase 1)

**Self-contained, per-file.** The audit needs only the ignore file's *own content*
— parse its patterns, test them against a probe set of canonical secret paths,
report misses. No whole-repo view and no secret-finding cross-reference (that is
Phase 2, deferred). This keeps it a pure function that both frontends can call.

## Detection

```ts
// pure; one ignore file in, findings out
export function auditIgnoreCoverage(path: string, content: string): InstructionFileIssue[]
```

1. Apply only to **AI-ignore files**: `.cursorignore`, `.claudeignore`,
   `.codeiumignore`, `.aiexclude` (NOT `.gitignore` / `.vetignore`).
2. Parse patterns with the shared gitignore matcher (see Building block).
3. **Intent gate** — only audit if the file shows secret-protection intent: at
   least one pattern contains `env|secret|credential|token|password|pem|key|rsa|
   npmrc|netrc`. (A `.cursorignore` that only ignores `node_modules/` isn't trying
   to protect secrets — don't nag it.)
4. Test the **probe set** of canonical secret paths; for each one no pattern
   matches, emit a gap with a suggested fix.

### Probe set → suggested fix

| Canonical secret path | Suggest if missing |
|---|---|
| `.env` (bare) — the flagship | `**/.env` |
| `prod.env` / `*.env` | `**/*.env` |
| `id_rsa`, `id_ed25519` | `**/id_rsa*`, `**/id_ed25519*` |
| `private.pem` / `*.pem` | `**/*.pem` |
| `server.key` / `*.key` | `**/*.key` |
| `credentials.json` / `*credential*` | `**/*credential*` |
| `.npmrc` | `**/.npmrc` |

### Rule

`ignore-coverage-gap` · **warning** · e.g.
> `.cursorignore` protects secret files but does not cover a bare `.env` (only
> `**/.env.*`) — it stays reachable by the AI. Add `**/.env`.

## Wiring
- **vet:** per-file. When `scanFile` sees an AI-ignore file (route by name), call
  `auditIgnoreCoverage(path, content)` and map its issues to `category: "integrity"`
  (or a new `"ignore"` category — see decisions). No repo-level pass needed.
- **Extension:** ContextBridge already detects ignore files but stores only paths;
  enrich it to load their **content**, then a pipeline step calls
  `auditIgnoreCoverage` per detected AI-ignore file.
- Emits via `instructionFileIssues` (existing channel); add `ignore-coverage-gap`
  to the `InstructionFileIssue["issue"]` union.

## Building block (shared)
Port vet's gitignore matcher (`vet/src/ignore.ts` `createIgnore`) into
`preflight-core` as a pure module so core can match patterns. Low-risk, reused by
Phase 2 and any future ignore-aware check.

## False-positive guards
- **Intent gate** (above) — no secret-ish patterns ⇒ no audit.
- Only AI-ignore files; never `.gitignore` (git tracking ≠ AI reach) or `.vetignore`.
- A probe path already covered ⇒ no finding (complete file is silent).
- Empty / malformed ignore file ⇒ no finding, no crash.
- Warning severity — advisory, never blocks a gate.

## Mandatory tests (QE)
- **TP:** `**/.env.*` present, bare `.env` absent → flag "misses bare .env" with
  the `**/.env` suggestion.
- **TP:** only `**/secret/**` → flags missing `.env`, `*.pem`, `*.key`, etc.
- **FP:** a complete file (`.env`, `**/.env.*`, `*.pem`, `*.key`, `*credential*`,
  `.npmrc`) → no findings.
- **FP (intent):** `.cursorignore` with only `node_modules/` `dist/` → no findings.
- **FP (wrong file):** the same patterns in `.gitignore` / `.vetignore` → not audited.
- **Boundary:** empty content, comments-only, malformed glob → no finding / no throw.
- **Matcher parity:** reuse the existing `.vetignore` matcher test corpus for the
  ported core module.

## Effort & phasing
- Port matcher to core: ~1–2 h.
- `auditIgnoreCoverage` + probe set + tests: ~2–3 h.
- vet routing + extension content-loading + wiring: ~2 h.
- Total ~0.5 day. Ships in a core patch; vet picks it up via the range; extension
  needs a republish to surface it.

## Open decisions (recommended answers)
1. **Category** — new `"ignore"` category vs reuse `"integrity"`. *Recommend
   `integrity`* (fewer moving parts; it's a config-integrity issue). Revisit if
   grouping matters.
2. **Probe-set breadth** — flagship bare-`.env` only, or the full table.
   *Recommend the full table but keep it tight* (the seven rows above); each row is
   a near-universal secret shape, low audit noise.
3. **Severity** — warning (recommended; posture issue, not an exploit).

## Out of scope (Phase 2, stays parked)
- Cross-referencing a real secret *finding* with ignore coverage ("this file has a
  secret AND isn't ignored") — needs ignore-file content + whole-repo view.
- Suppression-abuse detector (`.vetignore` hiding real secrets) — idea B, vet-only,
  stays in the backlog.
