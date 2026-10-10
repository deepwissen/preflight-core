# @deepwissen/preflight-core

Shared detection engine for **AI Preflight** — the analyzers behind the VS Code extension and the `vet` CLI.

Pure TypeScript, **zero platform dependencies** (no VS Code, no Node-only APIs beyond stdlib) so it runs anywhere and is fully unit-testable.

## What's inside
- **secret-scanner** — hardcoded secrets (4 layers) with credential-lifetime classification
- **trap-scanner** — "safe to read, not safe to auto-process" (unsafe deserialization, data-file traps)
- **integrity-scanner** — prompt-injection / hidden-unicode / bidi in instruction files
- **mcp-scanner** — MCP config hygiene (embedded secrets, tool poisoning, over-broad grants, unpinned servers)
- plus token estimation, waste detection, risk scoring, and the analyzer pipeline

## Usage
```ts
import { runPipeline, scanSecrets, detectTraps } from "@deepwissen/preflight-core";
```

All analysis is local and detect-only — nothing is modified or sent anywhere.
