const MAX_SESSIONS = 50;
const RE_PROMPT_THRESHOLD_MS = 30_000;
/**
 * Tracks analysis sessions and outcome signals to correlate
 * risk scores with user behavior (re-prompts, undos, etc.).
 *
 * Pure class — no VS Code imports. Persistence is injectable.
 */
export class OutcomeTracker {
    store;
    sessions;
    currentSession;
    lastAnalysisTimestamp = 0;
    constructor(store) {
        this.store = store;
        this.sessions = store?.loadSessions() ?? [];
        this.currentSession = this.createSession();
    }
    recordAnalysis(result) {
        const snapshot = {
            timestamp: result.timestamp,
            riskLevel: result.riskLevel,
            wastePatternIds: result.wastePatterns.map((wp) => wp.ruleId),
            suggestionIds: result.suggestions.map((s) => s.id),
            dismissedSuggestionIds: result.suggestions.filter((s) => s.dismissed).map((s) => s.id),
            actedSuggestionIds: [],
        };
        // Detect rapid re-analysis as potential re-prompt signal
        const gap = result.timestamp - this.lastAnalysisTimestamp;
        if (this.lastAnalysisTimestamp > 0 && gap < RE_PROMPT_THRESHOLD_MS) {
            this.recordSignal({
                type: "re-prompt",
                timestamp: result.timestamp,
                metadata: { gapMs: gap },
            });
        }
        this.currentSession.analyses.push(snapshot);
        this.lastAnalysisTimestamp = result.timestamp;
        this.persist();
    }
    recordSignal(signal) {
        this.currentSession.signals.push(signal);
        this.persist();
    }
    recordAction(suggestionId) {
        const lastAnalysis = this.currentSession.analyses[this.currentSession.analyses.length - 1];
        if (lastAnalysis) {
            lastAnalysis.actedSuggestionIds.push(suggestionId);
        }
        this.persist();
    }
    endSession() {
        this.currentSession.endTimestamp = Date.now();
        this.sessions.push(this.currentSession);
        // Rolling window
        if (this.sessions.length > MAX_SESSIONS) {
            this.sessions = this.sessions.slice(-MAX_SESSIONS);
        }
        this.currentSession = this.createSession();
        this.persist();
    }
    getSessionSummary() {
        const allSessions = [...this.sessions, this.currentSession];
        const allAnalyses = allSessions.flatMap((s) => s.analyses);
        const allSignals = allSessions.flatMap((s) => s.signals);
        const signalsByType = {};
        for (const signal of allSignals) {
            signalsByType[signal.type] = (signalsByType[signal.type] ?? 0) + 1;
        }
        const riskDistribution = {
            low: 0,
            medium: 0,
            high: 0,
        };
        for (const analysis of allAnalyses) {
            riskDistribution[analysis.riskLevel]++;
        }
        return {
            sessionCount: allSessions.length,
            totalAnalyses: allAnalyses.length,
            totalSignals: allSignals.length,
            signalsByType,
            riskDistribution,
        };
    }
    getCorrelations() {
        const allSessions = [...this.sessions, this.currentSession];
        const correlations = [];
        // Correlation 1: High risk sessions vs re-prompt rate
        const highRiskSessions = allSessions.filter((s) => s.analyses.some((a) => a.riskLevel === "high"));
        const lowRiskSessions = allSessions.filter((s) => s.analyses.every((a) => a.riskLevel !== "high"));
        if (highRiskSessions.length >= 3 && lowRiskSessions.length >= 3) {
            const highRePrompts = highRiskSessions
                .flatMap((s) => s.signals)
                .filter((sig) => sig.type === "re-prompt").length;
            const lowRePrompts = lowRiskSessions
                .flatMap((s) => s.signals)
                .filter((sig) => sig.type === "re-prompt").length;
            const highRate = highRePrompts / highRiskSessions.length;
            const lowRate = lowRePrompts / lowRiskSessions.length;
            const ratio = lowRate > 0 ? highRate / lowRate : highRate > 0 ? highRate : 0;
            correlations.push({
                label: "High risk re-prompt ratio",
                description: ratio > 0
                    ? `Sessions with HIGH risk have ${ratio.toFixed(1)}x more re-prompts`
                    : "No re-prompt correlation detected yet",
                sampleSize: highRiskSessions.length + lowRiskSessions.length,
                value: ratio,
            });
        }
        // Correlation 2: Dismissed warnings vs acted outcomes
        const dismissedSessions = allSessions.filter((s) => s.analyses.some((a) => a.dismissedSuggestionIds.length > 0));
        const actedSessions = allSessions.filter((s) => s.analyses.some((a) => a.actedSuggestionIds.length > 0));
        if (dismissedSessions.length >= 3 && actedSessions.length >= 3) {
            const dismissedSignals = dismissedSessions.flatMap((s) => s.signals).length;
            const actedSignals = actedSessions.flatMap((s) => s.signals).length;
            const dismissRate = dismissedSignals / dismissedSessions.length;
            const actedRate = actedSignals / actedSessions.length;
            correlations.push({
                label: "Dismissed vs acted outcomes",
                description: `Dismissing warnings: ${dismissRate.toFixed(1)} signals/session vs ${actedRate.toFixed(1)} when acting`,
                sampleSize: dismissedSessions.length + actedSessions.length,
                value: dismissRate > 0 ? actedRate / dismissRate : 0,
            });
        }
        return correlations;
    }
    createSession() {
        return {
            id: `session-${Date.now()}`,
            startTimestamp: Date.now(),
            endTimestamp: null,
            analyses: [],
            signals: [],
        };
    }
    persist() {
        this.store?.saveSessions([...this.sessions, this.currentSession]);
    }
}
//# sourceMappingURL=outcome-tracker.js.map