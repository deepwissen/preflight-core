import type { AnalysisResult, ContextSnapshot } from "../types.js";
/**
 * Adjusts risk level based on waste patterns and integrity findings.
 *
 * Runs AFTER token estimator, waste detector, and integrity scanner.
 * Reads their outputs from `partial` and boosts risk accordingly.
 *
 * Rules:
 *   Context-size baseline (budget-driven):
 *   - riskLevel starts at the budget band's risk, NOT the raw token band.
 *     This aligns risk with where output quality actually degrades
 *     (context rot) instead of a crude fixed-token cliff.
 *   - budget bands: lean → low, heavy → medium, bloated → high
 *
 *   Waste-based escalation (relative to that baseline):
 *   - waste found AND baseline is LOW  → bump to MEDIUM
 *   - waste >= 2  AND baseline is MEDIUM → bump to HIGH
 *   - HIGH stays HIGH regardless
 *
 *   Security-sensitive waste (independent escalation):
 *   - sensitive-file or env-file on LOW → at least MEDIUM
 *
 *   Integrity-based (minimum floor):
 *   - any integrity finding with severity "error"   → at least HIGH
 *   - any integrity finding with severity "warning"  → at least MEDIUM
 *   - severity "info" does not affect risk level
 */
export declare function scoreRisk(context: ContextSnapshot, partial: Partial<AnalysisResult>): Partial<AnalysisResult>;
//# sourceMappingURL=risk-scorer.d.ts.map