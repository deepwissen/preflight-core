import type { AnalysisResult, ContextSnapshot } from "../types.js";
/**
 * Detects common patterns that waste tokens or degrade AI responses.
 * Rule-based — no ML. Each rule is transparent and configurable.
 */
export declare function detectWaste(context: ContextSnapshot, partial: Partial<AnalysisResult>): Partial<AnalysisResult>;
//# sourceMappingURL=waste-detector.d.ts.map