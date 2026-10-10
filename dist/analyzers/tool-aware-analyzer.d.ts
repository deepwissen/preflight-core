import type { AnalysisResult, ContextSnapshot } from "../types.js";
/**
 * Tool-aware analyzer — runs LAST in the pipeline.
 * Uses the active tool profile to:
 *   F1:  Compute context window usage (truncation %) + budget band (quality)
 *   F1b: Warn about context budget pressure (context rot) regardless of window %
 *   F2: Detect missing tool-specific instruction files
 *   F3: Check instruction file quality (line counts)
 *   F4: Detect missing ignore files
 *   F5: Suppress tab-related waste patterns for tools where tabs don't matter
 *   F6: Warn about long conversation history
 *   F8: Detect imports in selection that are missing from context
 *   F9: Warn about truncation risk when context usage is high
 */
export declare function detectToolAwareIssues(context: ContextSnapshot, partial: Partial<AnalysisResult>): Partial<AnalysisResult>;
//# sourceMappingURL=tool-aware-analyzer.d.ts.map