export { estimateTokens } from "./token-estimator.js";
export { detectWaste } from "./waste-detector.js";
export { scanInstructionIntegrity } from "./integrity-scanner.js";
export { scanMcpConfigs } from "./mcp-scanner.js";
export { scanAgentConfig } from "./agent-config-scanner.js";
export {
  auditDetectedExposure,
  auditIgnoreCoverage,
  isAiIgnoreFile,
  IGNORE_CAVEAT,
  DETECTION_DISCLAIMER,
  type AiIgnoreFile,
} from "./ignore-coverage.js";
export { scanSecrets } from "./secret-scanner.js";
export { detectTraps } from "./trap-scanner.js";
export { scoreRisk } from "./risk-scorer.js";
export { detectPositiveSignals } from "./positive-signals.js";
export { detectToolAwareIssues } from "./tool-aware-analyzer.js";
export { analyzePrompt, extractIntentKeywords } from "./prompt-analyzer.js";
export {
  rankWorkspaceMatches,
  groupWorkspaceMatches,
  formatMatchReason,
} from "./workspace-ranker.js";
