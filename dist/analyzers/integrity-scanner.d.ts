import type { AnalysisResult, ContextSnapshot } from "../types.js";
/**
 * Scans instruction file content for integrity issues:
 * - Hidden unicode characters
 * - Bidi override characters
 * - Suspicious prompt injection patterns
 *
 * When multiple categories fire on the same line, the findings are
 * elevated to "error" severity (compound attack detection).
 *
 * Runs after detectWaste, before scoreRisk.
 */
export declare function scanInstructionIntegrity(context: ContextSnapshot, _partial: Partial<AnalysisResult>): Partial<AnalysisResult>;
//# sourceMappingURL=integrity-scanner.d.ts.map