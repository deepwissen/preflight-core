import type { AnalysisResult, ContextSnapshot } from "../types.js";
export declare function shannonEntropy(str: string): number;
/**
 * Scans the active file's content for hardcoded secrets using 4 detection layers:
 *   Layer 1: Known provider prefixes (AWS, GitHub, Stripe, etc.) — severity: error
 *   Layer 2: Keyword + literal value (password, secret, token, etc.) — severity: warning
 *   Layer 3: Shannon entropy on quoted strings — severity: warning
 *   Layer 4: Connection strings (mongodb://, postgres://, etc.) — severity: warning
 *   Layer 5: Context filtering applied inline (skip comments, test files, placeholders)
 */
export declare function scanSecrets(context: ContextSnapshot, _partial: Partial<AnalysisResult>): Partial<AnalysisResult>;
//# sourceMappingURL=secret-scanner.d.ts.map