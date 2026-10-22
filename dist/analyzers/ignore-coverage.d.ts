import type { InstructionFileIssue } from "../types.js";
/**
 * AI-ignore checks — see docs/ignore-coverage-audit.md.
 *
 * CRITICAL framing: an ignore file is a *request, not a wall*. The tool may not
 * honour it and an agent's Read/Bash calls bypass it entirely. So:
 *   - A detected secret in the working tree is reachable by the AI whether or not
 *     an ignore pattern "covers" it. Coverage is NOT a dividing line — it's a weak
 *     secondary note at most.
 *   - Nothing here emits a positive verdict, and no output string uses confidence
 *     words (safe / protected / secure / complete) — enforced by a test.
 *   - A clean scan is bounded by scanner recall; consumers MUST surface
 *     DETECTION_DISCLAIMER so "0 findings" never reads as "no secrets present".
 *   - The caveat is shown ONCE per report by the consumer (IGNORE_CAVEAT), not
 *     repeated on every finding (repetition breeds caveat-blindness).
 */
/** Shown ONCE per report by the consumer — not repeated per finding. */
export declare const IGNORE_CAVEAT: string;
/** Consumers MUST surface this on a clean scan — recall is bounded. */
export declare const DETECTION_DISCLAIMER: string;
export declare function isAiIgnoreFile(path: string): boolean;
export interface AiIgnoreFile {
    path: string;
    content: string;
}
/**
 * PRIMARY (detected exposure): EVERY file with a detected secret sits in the
 * working tree and is reachable by the AI — ignore coverage does not change that.
 * One consolidated finding. Coverage appears only as a weak secondary note, never
 * as a divider between "exposed" and "safe".
 */
export declare function auditDetectedExposure(secretFilePaths: string[], aiIgnoreFiles: AiIgnoreFile[]): InstructionFileIssue[];
/**
 * SECONDARY (hygiene lint): canonical-shape coverage gaps in one AI-ignore file.
 * Only runs when the file shows secret-protection intent. Never asserts
 * completeness; the per-finding suggestion carries only the fix line — the full
 * caveat is shown once per report.
 */
export declare function auditIgnoreCoverage(path: string, content: string): InstructionFileIssue[];
//# sourceMappingURL=ignore-coverage.d.ts.map