import type { InstructionFileIssue } from "../types.js";
import { createIgnore } from "../ignore-match.js";

/**
 * AI-ignore coverage audit (rule `ignore-coverage-gap`).
 *
 * Teams use `.cursorignore` / `.claudeignore` to keep secret files away from the
 * AI, but the patterns routinely miss what people think they cover — the classic
 * being a `.env.*` glob, which does NOT match a bare `.env`. This audits an
 * AI-ignore file's own patterns against a probe set of canonical secret paths and
 * reports the gaps, so "it looks protective but isn't" is caught.
 *
 * Self-contained per file: needs only the ignore file's content. See
 * docs/ignore-coverage-audit.md.
 */

/** AI-tool ignore files whose job is to keep content away from the model. */
const AI_IGNORE_FILE = /(^|\/)\.(cursorignore|claudeignore|codeiumignore|aiexclude)$/i;

/** The file is trying to protect secrets if any pattern mentions a secret-ish term. */
const SECRET_INTENT =
  /env|secret|credential|token|password|passwd|pem|key|rsa|npmrc|netrc|pfx|keystore|p12/i;

// Canonical secret paths every secret-protecting AI-ignore should cover, with the
// pattern to suggest when it's missing.
const PROBES: Array<{ path: string; label: string; suggest: string }> = [
  { path: ".env", label: "a bare .env", suggest: "**/.env" },
  { path: "prod.env", label: "*.env files", suggest: "**/*.env" },
  { path: "id_rsa", label: "SSH private keys (id_rsa)", suggest: "**/id_rsa*" },
  { path: "private.pem", label: "PEM private keys", suggest: "**/*.pem" },
  { path: "server.key", label: "key files", suggest: "**/*.key" },
  { path: "credentials.json", label: "credential files", suggest: "**/*credential*" },
  { path: ".npmrc", label: ".npmrc (may hold a token)", suggest: "**/.npmrc" },
];

function isAiIgnoreFile(path: string): boolean {
  return AI_IGNORE_FILE.test(path);
}

/**
 * Audit a single AI-ignore file's content. Returns a finding per uncovered
 * canonical secret path — but only when the file shows secret-protection intent
 * (so a `.cursorignore` that only ignores `node_modules/` is never nagged).
 */
export function auditIgnoreCoverage(path: string, content: string): InstructionFileIssue[] {
  if (!isAiIgnoreFile(path) || !content) return [];

  const ignore = createIgnore(content.split("\n"));
  if (ignore.patternCount === 0) return [];
  if (!ignore.patterns.some((p) => SECRET_INTENT.test(p))) return []; // no intent → no audit

  const name = path.split("/").pop() ?? path;
  const issues: InstructionFileIssue[] = [];
  for (const probe of PROBES) {
    if (ignore.matchPath(probe.path)) continue; // covered
    issues.push({
      id: `ignore-coverage-gap-${probe.suggest}-${path}`,
      filePath: path,
      issue: "ignore-coverage-gap",
      severity: "warning",
      matchedText: probe.suggest,
      description: `${name} protects secret files but does not cover ${probe.label} — it stays reachable by the AI`,
      suggestion: `Add \`${probe.suggest}\` to ${name}`,
    });
  }
  return issues;
}
