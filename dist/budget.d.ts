import type { BudgetBand, BudgetThresholds, RiskLevel, TokenEstimate } from "./types.js";
/**
 * Context-budget classification — shared by the tool-aware analyzer (which
 * surfaces the band in the UI) and the risk scorer (which uses it as a floor).
 *
 * The bands are ≈absolute, chosen so "lean" stays clear of lost-in-the-middle
 * effects and "bloated" sits in the context-rot curve — independent of the
 * tool's nominal context window. Overridable via ai-preflight.budget.* config.
 */
export declare const DEFAULT_BUDGET_THRESHOLDS: BudgetThresholds;
export declare function classifyBudget(tokens: number, t: BudgetThresholds): BudgetBand;
/** Midpoint of the token-estimate range — the single absolute figure
 *  analyzers reason about. */
export declare function midpointTokens(est: Pick<TokenEstimate, "low" | "high">): number;
/** Context-size risk implied by a budget band. */
export declare function budgetBandToRisk(band: BudgetBand): RiskLevel;
//# sourceMappingURL=budget.d.ts.map