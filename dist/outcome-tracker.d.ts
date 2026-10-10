import type { AnalysisResult, OutcomeSignal, SessionRecord, SessionSummary, OutcomeCorrelation } from "./types.js";
/**
 * Injectable persistence interface.
 * Platform layer provides the implementation (e.g., workspace state).
 */
export interface OutcomeStore {
    loadSessions(): SessionRecord[];
    saveSessions(sessions: SessionRecord[]): void;
}
/**
 * Tracks analysis sessions and outcome signals to correlate
 * risk scores with user behavior (re-prompts, undos, etc.).
 *
 * Pure class — no VS Code imports. Persistence is injectable.
 */
export declare class OutcomeTracker {
    private store?;
    private sessions;
    private currentSession;
    private lastAnalysisTimestamp;
    constructor(store?: OutcomeStore | undefined);
    recordAnalysis(result: AnalysisResult): void;
    recordSignal(signal: OutcomeSignal): void;
    recordAction(suggestionId: string): void;
    endSession(): void;
    getSessionSummary(): SessionSummary;
    getCorrelations(): OutcomeCorrelation[];
    private createSession;
    private persist;
}
//# sourceMappingURL=outcome-tracker.d.ts.map