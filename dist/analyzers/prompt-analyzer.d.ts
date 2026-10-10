import type { ContextSnapshot, AnalysisResult, PromptAnalysis, WorkspaceMatch } from "../types.js";
/**
 * Analyzes a user's prompt text against their current IDE context.
 * Pure function — no VS Code imports. Used only by the @preflight chat participant.
 *
 * Design principle: precision over recall.
 * Only surface findings backed by high-confidence signals (explicit file refs,
 * path refs, module patterns). Generic words never drive warnings.
 */
export declare function analyzePrompt(promptText: string, context: ContextSnapshot, _result: AnalysisResult, workspaceMatches?: WorkspaceMatch[]): PromptAnalysis;
export declare function extractIntentKeywords(promptText: string): {
    high: string[];
    all: string[];
};
//# sourceMappingURL=prompt-analyzer.d.ts.map