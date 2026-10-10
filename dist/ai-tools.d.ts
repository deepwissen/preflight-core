import type { AiToolId } from "./types.js";
/**
 * AI tool registry — pure data, no VS Code imports.
 * Contains context window sizes, instruction file patterns,
 * ignore files, and model variants for each supported AI tool.
 */
export interface AiToolModel {
    id: string;
    displayName: string;
    contextWindowTokens: number;
}
export interface AiToolDefinition {
    id: AiToolId;
    displayName: string;
    provider: string;
    contextWindowTokens: number;
    instructionFiles: string[];
    ignoreFiles: string[];
    tabsAffectContext: boolean;
    models?: AiToolModel[];
}
export declare const AI_TOOLS: Record<AiToolId, AiToolDefinition>;
/**
 * Returns the effective context window size, considering an optional model override.
 */
export declare function getContextWindowTokens(toolId: AiToolId, modelId?: string): number;
//# sourceMappingURL=ai-tools.d.ts.map