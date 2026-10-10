import type { WorkspaceMatch } from "../types.js";
export declare function scoreMatch(match: WorkspaceMatch): number;
/**
 * Returns a human-friendly label for why this match was found.
 */
export declare function formatMatchReason(match: WorkspaceMatch): string;
export declare function rankWorkspaceMatches(matches: WorkspaceMatch[]): WorkspaceMatch[];
/**
 * Ranks, filters, and groups matches into "strongly related" and "possibly related" buckets.
 * Calls rankWorkspaceMatches internally — callers don't need to pre-sort.
 */
export declare function groupWorkspaceMatches(matches: WorkspaceMatch[]): {
    strong: WorkspaceMatch[];
    possible: WorkspaceMatch[];
};
//# sourceMappingURL=workspace-ranker.d.ts.map