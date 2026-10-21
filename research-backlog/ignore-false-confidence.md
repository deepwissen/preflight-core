# Research stub: "Ignore files create false confidence" (two detectors)

> **Status:** PARKED — concept + implementation plan. Internal, do not publish.
> Both detectors flag a *meta*-vulnerability: an ignore/allowlist that people
> trust to protect them but doesn't. Surfaced from a real user scenario.

Two sides of one insight: ignore files are treated as security controls, but a
gap or a misuse silently removes protection.

- **A. Ignore-coverage gap** — a secret file an AI-tool ignore (`.cursorignore`,
  `.claudeignore`, `.codeiumignore`, `.aiexclude`) is *supposed* to hide, but the
  patterns don't actually match it, so it stays AI-reachable.
- **B. Suppression abuse** — a `.vetignore` / `vet:allow` used to hide
  secret-bearing paths from the scanner itself (silencing a true positive instead
  of fixing it).

Differentiator: almost no scanner audits the *completeness of an AI-ignore file*
or its *own allowlist* for self-inflicted blind spots.

---

## A. Ignore-coverage gap

### Threat
A repo's `.cursorignore` has `**/.env.*` — which matches `.env.local` but **not a
bare `.env`**. The team believes secrets are hidden from the AI; the most common
secret file is not. Same for `**/secret/**` (only files *inside* a `secret/` dir;
misses `credentials.json`, `*.pem`, `config/secret.yaml`).

### Detection
A pure helper + two wirings:

- **Core:** `checkIgnoreCoverage(secretFilePaths: string[], ignorePatterns: string[])`
  — reuse the gitignore matcher (port vet's `createIgnore` into core as a shared
  pure module). Returns the secret files NOT covered by any pattern.
- Plus a **completeness audit** against canonical secret paths
  (`.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `credentials.*`, `secrets/…`):
  report which canonical shapes the ignore file fails to cover (catches the bare
  `.env` gap even with no current secret present).

### Wiring
- **Extension:** new pipeline step `scanIgnoreCoverage(context)` running AFTER
  `scanSecrets` — reads `partial.secretFindings` + the repo's ignore-file content
  (ContextBridge must load ignore-file *content*, not just paths, into the
  snapshot). Emits findings for secret files not AI-ignored.
- **vet:** a post-scan pass in `cli.ts` — after the scan loop, collect the files
  that produced secret findings, load `.cursorignore`/`.claudeignore` from the
  scan root, run `checkIgnoreCoverage`, print gaps.

### Rule
`ignore-coverage-gap` · **warning** · "File X contains a secret but is not matched
by .cursorignore/.claudeignore — it remains reachable by the AI." And the audit
variant: "`.cursorignore` has `**/.env.*` but not a bare `.env`."

### FP guards
- Only consider files that actually have a secret finding (Phase 2) or canonical
  secret-name shapes (Phase 1). Don't flag arbitrary unignored files.
- `.gitignore` is not an AI-ignore — only check AI-tool ignore files for this.

### Phasing
- **Phase 1** (cheap, high-value): completeness audit of AI-ignore files against
  canonical secret shapes. No secret-finding cross-ref needed. Catches the bare
  `.env` gap. Pure function + report.
  **→ PROMOTED to a scheduled design: `docs/ignore-coverage-audit.md`.**
- **Phase 2** (still parked): cross-reference real secret findings with ignore
  coverage (needs ignore-file content in the snapshot + the whole-repo view).

---

## B. Suppression abuse (`.vetignore` / `vet:allow` hiding real secrets)

### Threat
`.cursorignore` (hide from AI) and `.vetignore` (hide from scanner) look alike, so
users copy secret patterns into `.vetignore` — or they `.vetignore` a `.env` to
silence a *correct* finding. Either way the scanner is told to skip exactly the
files most likely to hold real credentials: a self-inflicted blind spot.

### Detection
- **vet only** (`.vetignore` is a vet concept). When `loadIgnore` parses
  `.vetignore`, inspect each pattern for secret-shaped tokens:
  `env`, `secret`, `credential`, `token`, `password`, `pem`, `key`, `p12`,
  `id_rsa`, `npmrc`, `netrc`, `keystore`, `pfx`.
- Emit an advisory: "`.vetignore` excludes `<pattern>` — this hides files that
  typically contain real secrets. Only allowlist false-positive sources (test
  fixtures, generated code, docs)."

### Rule
`vetignore-hides-secrets` · **warning** (advisory, printed with the run — about
the *config*, not a code finding).

### FP guards
- `.env.example` / `.env.template` / `*.sample` patterns are examples — exempt.
- A pattern under a clearly-fixture path (`test/`, `fixtures/`, `examples/`) is
  likely benign — downgrade or exempt.
- Allow an explicit acknowledgement comment (`# vet-ack: intentional`) on the line
  to silence, so a deliberate choice isn't nagged.

### Phasing
- **Phase 1** (cheap): keyword scan of `.vetignore` lines → advisory. Sufficient.
- **Phase 2** (precise, optional): only warn if the ignored path *would* have
  produced a finding (scan it without the ignore) — expensive; skip unless asked.

---

## Shared building block
Both need a **gitignore glob matcher in core**. vet already has one
(`src/ignore.ts` `createIgnore`) — port it to `preflight-core` as a shared pure
module so core/extension can match ignore patterns too. Low-risk, reusable.

## Open decisions
1. Severity: both `warning` (advisory, non-blocking) vs one as `error`? Lean
   warning — they're posture issues, not an exploit on their own.
2. Scope A to AI-ignore files only, or also warn when a secret file is in neither
   `.gitignore` nor the AI-ignore? (The latter is broader "secret not ignored at
   all" — useful but noisier.)
3. Canonical secret-shape list: keep tight (`.env`, `*.pem`, `*.key`,
   `credentials`, `id_rsa`, `.npmrc`) to avoid audit noise.
