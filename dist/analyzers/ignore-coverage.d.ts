import type { InstructionFileIssue } from "../types.js";
/**
 * Audit a single AI-ignore file's content. Returns a finding per uncovered
 * canonical secret path — but only when the file shows secret-protection intent
 * (so a `.cursorignore` that only ignores `node_modules/` is never nagged).
 */
export declare function auditIgnoreCoverage(path: string, content: string): InstructionFileIssue[];
//# sourceMappingURL=ignore-coverage.d.ts.map