import type { AnalysisResult, AnalyzerStep, ContextSnapshot } from "./types.js";
/**
 * Runs a context snapshot through an ordered list of analyzer steps.
 * Each step receives the context and the accumulated partial result.
 * Steps are independent — a failing step doesn't block others.
 */
export declare function runPipeline(context: ContextSnapshot, steps: AnalyzerStep[]): AnalysisResult;
//# sourceMappingURL=pipeline.d.ts.map