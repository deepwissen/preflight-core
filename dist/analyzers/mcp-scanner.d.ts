import type { AnalysisResult, ContextSnapshot } from "../types.js";
/**
 * Scans MCP config files for security issues:
 *   1. Embedded secrets in env/url/headers
 *   2. Tool description poisoning (unicode, bidi, injection)
 *   3. Unknown/untrusted server connections
 *   4. Risky config patterns
 */
export declare function scanMcpConfigs(context: ContextSnapshot, _partial: Partial<AnalysisResult>): Partial<AnalysisResult>;
//# sourceMappingURL=mcp-scanner.d.ts.map