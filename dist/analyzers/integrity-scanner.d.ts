import type { AnalysisResult, ContextSnapshot } from "../types.js";
/**
 * Scans agent-trusted content for integrity issues (hidden unicode, bidi
 * overrides, LLM role-tag spoofing, and — for prose surfaces — suspicious
 * injection phrases) across three surfaces:
 * - AI instruction files (CLAUDE.md, .cursorrules, …) — all detectors
 * - MCP config files — near-zero-FP detectors only (no phrase matching on
 *   structured config); catches invisible/bidi payloads a reviewer can't see
 * - a prompt/template file when it is the active file (.prompt, .prompty, …)
 *
 * When multiple categories fire on the same line of a file, the findings are
 * elevated to "error" severity (compound attack detection).
 *
 * Runs after detectWaste, before scoreRisk.
 */
export declare function scanInstructionIntegrity(context: ContextSnapshot, _partial: Partial<AnalysisResult>): Partial<AnalysisResult>;
//# sourceMappingURL=integrity-scanner.d.ts.map