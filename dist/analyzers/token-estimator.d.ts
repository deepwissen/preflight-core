import type { AnalysisResult, ContextSnapshot } from "../types.js";
/**
 * Estimates token count from context sources.
 *
 * Uses characters / CHARS_PER_TOKEN as a heuristic.
 * Returns a range (low–high) rather than a single number
 * to avoid false precision.
 */
export declare function estimateTokens(context: ContextSnapshot, _partial: Partial<AnalysisResult>): Partial<AnalysisResult>;
//# sourceMappingURL=token-estimator.d.ts.map