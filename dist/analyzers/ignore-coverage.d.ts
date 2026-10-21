import type { InstructionFileIssue } from "../types.js";
export declare function isAiIgnoreFile(path: string): boolean;
export interface AiIgnoreFile {
    path: string;
    content: string;
}
/**
 * PRIMARY (ground truth): files where a scanner actually found a secret that no
 * AI-ignore pattern covers. Fires loudest on the careless case — a secret present
 * with no protective patterns (or no AI-ignore file at all) → everything exposed.
 * Consolidated into one finding (the remediation is the same for all: get them out).
 */
export declare function auditSecretExposure(secretFilePaths: string[], aiIgnoreFiles: AiIgnoreFile[]): InstructionFileIssue[];
/**
 * SECONDARY (hygiene lint): canonical-shape coverage gaps in one AI-ignore file.
 * Only runs when the file shows secret-protection intent (it's lint for files that
 * are *trying*). Never asserts completeness — the canon is necessarily partial.
 */
export declare function auditIgnoreCoverage(path: string, content: string): InstructionFileIssue[];
//# sourceMappingURL=ignore-coverage.d.ts.map