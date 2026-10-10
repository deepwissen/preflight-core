/**
 * Shared import path extraction patterns.
 * Used by prompt-analyzer (missing context detection) and tool-aware-analyzer (context gap detection).
 * Also used by workspace-searcher for import graph traversal.
 */
export declare const IMPORT_PATTERNS: RegExp[];
/**
 * Extracts relative import paths from source text.
 * Returns deduplicated array of raw import paths (e.g., './utils/helpers').
 */
export declare function extractImportPaths(sourceText: string): string[];
//# sourceMappingURL=import-patterns.d.ts.map