# Research backlog

> **Internal research notes — NOT for publication.** These are parked product/
> detection ideas, not roadmap commitments. Do **not** turn into blog posts,
> announcements, or marketing without a separate decision. Excluded from the npm
> package (`files: ["dist"]`). Note: this repo is public, so the folder is visible
> on GitHub — keep anything truly sensitive out of here.

Each idea was evaluated against the same bar: **fit × feasibility × false-positive
risk × differentiation**, under a standing PO view that **adoption — not detection
depth — is the current binding constraint.** Most are parked deliberately.

## Parked ideas

| Idea | Fit | Status / why parked |
|---|---|---|
| [Agent BOM](./agent-bom.md) — inventory the agent's tool/context supply chain | High, in-niche | Reporting feature (not a gate), demand unproven → parked behind adoption |
| [Ignore false-confidence](./ignore-false-confidence.md) — (A) secret files an incomplete `.cursorignore`/`.claudeignore` fails to hide; (B) `.vetignore`/`vet:allow` hiding real-secret paths from the scanner | High, in-niche, novel | **A-Phase-1 PROMOTED → scheduled design in [`docs/ignore-coverage-audit.md`](../docs/ignore-coverage-audit.md).** A-Phase-2 (real-finding cross-ref) and B (suppression abuse) stay parked here |
| **Agent-scoped Zero-Trust detection** — unrestricted egress / `allowedHosts: ["*"]` / no-auth MCP servers in agent & MCP config | High, in-niche | Strongest *next detection* increment if/when we add detection; extends MCP + agent scanners, low FP |
| **Agent scanner Phase 2** — deeper tool-specific keys (Cline/Roo, Aider, Codex, Continue) | Medium | Generic flag rules already catch most; tool-specific keys drift between versions → maintenance cost. Add only on demand |
| **A2: per-tool capability classification** (is an auto-approved tool network/exec/write?) | Low | Needs a maintained tool-capability registry; FP + upkeep cost. Deferred |
| **B-broad: injection-phrase scanning of all prose/docs** | Low | FP swamp ("ignore the above" appears innocently everywhere) — violates FP-first ethos. Deferred |
| **Conservative PII detection** (Luhn-valid cards, SSNs, private keys only; never emails) | Medium | Classic FP generator; only viable tightly scoped. Deferred until asked |

## Decided (not parked — recorded so we don't re-litigate)

| Topic | Decision |
|---|---|
| **Dependency SBOM / SCA** (Syft/Grype/Trivy/OSV/Dependabot space) | **Integrate, don't rebuild.** Commodity; breaks vet's local/zero-dep/offline promise (needs a vuln DB). Position vet as the agent-security layer SCA can't see; run both → one SARIF dashboard |
| **General IaC / cloud posture** (checkov/tfsec/Wiz space) | Out of scope — commodity, off-mission. Complementary, not ours |
| **Runtime defenses** (sandboxes, live classifiers, endpoint/behavioral monitoring, dataflow) | Out of scope — different layer. vet is the static/shift-left complement, not a replacement |
| **SQL injection / XSS / SSRF** (taint/dataflow) | Out of scope — needs a dataflow engine; leave to Semgrep/CodeQL |
| **Zero Trust for AI agents** (framing) | *Positioning*, not a backlog build — vet's existing agent/credential/MCP checks already map to NIST 800-207 tenets. (Content lives outside this folder) |

## How to use this folder

- Add a one-line row above when an idea gets parked, with the honest reason.
- Promote an idea by writing its full design doc into `../docs/` (like
  `agent-autonomy-scanner.md`) and flipping its status here.
- Keep the "Decided — out of scope" table current so we stop re-asking the same
  "should vet also do X?" questions.
