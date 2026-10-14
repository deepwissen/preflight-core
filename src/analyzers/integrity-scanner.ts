import type { AnalysisResult, ContextSnapshot, InstructionFileIssue } from "../types.js";

// Hidden unicode characters that could be used to hide content
/* eslint-disable no-misleading-character-class */
const HIDDEN_UNICODE =
  /[\u200B\u200C\u200D\u2060\u00AD\u034F\u17B4\u17B5\u180E\u2062\u2063\u2064]/g;
/* eslint-enable no-misleading-character-class */
const TAG_CHARS = /[\u{E0001}-\u{E007F}]/gu;

// Bidi override characters that can visually reorder text
const BIDI_OVERRIDES =
  /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069\u061C\u200E\u200F]/g;

// Suspicious prompt injection patterns
const SUSPICIOUS_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+(instructions|rules|guidelines)/i,
  /disregard\s+(all\s+)?(above|previous|prior)\s+(instructions|rules)/i,
  /(?:new|override|replace)\s+instructions?\s*:/i,
  /^\s*system\s*:/im,
  /\[]\(https?:\/\/[^)]+\)/, // hidden markdown links
];

// LLM role / turn delimiters embedded in content that isn't a chat transcript —
// a prompt-injection ("role spoofing") attempt. Restricted to LLM-specific tokens
// (ChatML / Llama) so bare `<system>` or `### System:` in prose is NOT flagged.
const ROLE_TAGS = /<\|(?:im_start|im_end|system|user|assistant)\|>|\[\/?INST\]|<<\/?SYS>>/i;

// Prompt/template files an agent ingests as trusted instructions (extension-typed
// — not bare `prompts/` dirs, which hold mixed non-agent text).
const PROMPT_FILE = /\.(prompt|prompty)$|\.chatmode\.md$|(^|\/)\.github\/prompts\//i;

/** Severity by issue category (security-informed). */
const ISSUE_SEVERITY: Record<string, InstructionFileIssue["severity"]> = {
  "suspicious-instruction": "warning", // unambiguous attack pattern
  "bidi-override": "warning", // high risk, rarely legitimate
  "hidden-unicode": "info", // could be accidental encoding issue
  "role-tag-spoofing": "warning", // LLM role delimiter in non-transcript content
};

/**
 * Scans agent-trusted content for integrity issues (hidden unicode, bidi
 * overrides, LLM role-tag spoofing, and — for prose surfaces — suspicious
 * injection phrases) across three surfaces:
 * - AI instruction files (CLAUDE.md, .cursorrules, …) — all detectors
 * - MCP config files — near-zero-FP detectors only (no phrase matching on
 *   structured config); catches invisible/bidi payloads a reviewer can't see
 * - a prompt/template file when it is the active file (.prompt, .prompty, …)
 *
 * When multiple categories fire on the same line of a file, the findings are
 * elevated to "error" severity (compound attack detection).
 *
 * Runs after detectWaste, before scoreRisk.
 */
export function scanInstructionIntegrity(
  context: ContextSnapshot,
  _partial: Partial<AnalysisResult>
): Partial<AnalysisResult> {
  const instructionFileIssues: InstructionFileIssue[] = [];
  const seen = new Set<string>();

  // Scan one surface; `phrases` enables the injection-phrase heuristic (prose
  // surfaces only — not structured MCP config).
  const scanOne = (path: string, content: string, phrases: boolean): void => {
    const before = instructionFileIssues.length;
    scanHiddenUnicode(path, content, instructionFileIssues);
    scanBidiOverrides(path, content, instructionFileIssues);
    scanRoleTags(path, content, instructionFileIssues);
    if (phrases) scanSuspiciousInstructions(path, content, instructionFileIssues);
    elevateCompound(instructionFileIssues.slice(before));
  };

  for (const file of context.aiInstructionFiles) {
    if (!file.content) continue;
    scanOne(file.path, file.content, true);
    seen.add(file.path);
  }
  for (const file of context.mcpConfigFiles ?? []) {
    if (!file.content || seen.has(file.path)) continue;
    scanOne(file.path, file.content, false);
    seen.add(file.path);
  }
  const active = context.activeFile;
  if (active?.content && PROMPT_FILE.test(active.path) && !seen.has(active.path)) {
    scanOne(active.path, active.content, true);
  }

  return { wastePatterns: [], instructionFileIssues };
}

/** Elevate findings to "error" when 2+ categories hit the same line (compound attack). */
function elevateCompound(fileIssues: InstructionFileIssue[]): void {
  if (fileIssues.length < 2) return;
  const byLine = new Map<number, InstructionFileIssue[]>();
  for (const issue of fileIssues) {
    if (issue.lineNumber == null) continue;
    const group = byLine.get(issue.lineNumber) ?? [];
    group.push(issue);
    byLine.set(issue.lineNumber, group);
  }
  for (const [, group] of byLine) {
    if (group.length >= 2) {
      for (const issue of group) {
        issue.severity = "error";
        issue.description += " [compound attack — multiple techniques on same line]";
      }
    }
  }
}

function scanHiddenUnicode(
  filePath: string,
  content: string,
  issues: InstructionFileIssue[]
): void {
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check for hidden unicode
    HIDDEN_UNICODE.lastIndex = 0;
    const hiddenMatch = HIDDEN_UNICODE.exec(line);
    if (hiddenMatch) {
      const codePoint = hiddenMatch[0].codePointAt(0)!.toString(16).toUpperCase();
      addIssue(
        filePath,
        "hidden-unicode",
        i + 1,
        `U+${codePoint}`,
        `Hidden unicode character (U+${codePoint}) in ${fileName(filePath)} line ${i + 1}`,
        "Remove hidden unicode characters — they may be used to hide malicious instructions",
        issues
      );
      return; // One finding per category per file
    }

    // Check for tag characters
    TAG_CHARS.lastIndex = 0;
    const tagMatch = TAG_CHARS.exec(line);
    if (tagMatch) {
      const codePoint = tagMatch[0].codePointAt(0)!.toString(16).toUpperCase();
      addIssue(
        filePath,
        "hidden-unicode",
        i + 1,
        `U+${codePoint}`,
        `Hidden tag character (U+${codePoint}) in ${fileName(filePath)} line ${i + 1}`,
        "Remove hidden unicode characters — they may be used to hide malicious instructions",
        issues
      );
      return;
    }

    // Check for BOM not at position 0
    if (i === 0 && line.length > 0 && line.charCodeAt(0) === 0xfeff) {
      // BOM at position 0 in first line is normal — skip
      continue;
    }
    if (line.includes("\uFEFF")) {
      const pos = line.indexOf("\uFEFF");
      if (i > 0 || pos > 0) {
        addIssue(
          filePath,
          "hidden-unicode",
          i + 1,
          "U+FEFF",
          `Hidden BOM character in ${fileName(filePath)} line ${i + 1}`,
          "Remove hidden unicode characters — they may be used to hide malicious instructions",
          issues
        );
        return;
      }
    }
  }
}

function scanBidiOverrides(
  filePath: string,
  content: string,
  issues: InstructionFileIssue[]
): void {
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    BIDI_OVERRIDES.lastIndex = 0;
    const match = BIDI_OVERRIDES.exec(lines[i]);
    if (match) {
      const codePoint = match[0].codePointAt(0)!.toString(16).toUpperCase();
      addIssue(
        filePath,
        "bidi-override",
        i + 1,
        `U+${codePoint}`,
        `Bidi override character (U+${codePoint}) in ${fileName(filePath)} line ${i + 1}`,
        "Remove bidi override characters — they can visually hide malicious instructions",
        issues
      );
      return; // One finding per category per file
    }
  }
}

function scanRoleTags(filePath: string, content: string, issues: InstructionFileIssue[]): void {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    ROLE_TAGS.lastIndex = 0;
    const match = ROLE_TAGS.exec(lines[i]);
    if (match) {
      addIssue(
        filePath,
        "role-tag-spoofing",
        i + 1,
        match[0],
        `LLM role delimiter "${match[0]}" in ${fileName(filePath)} line ${i + 1}`,
        "Content uses chat role/turn markers — a prompt-injection (role spoofing) attempt; remove them",
        issues
      );
      return; // one finding per category per file
    }
  }
}

function scanSuspiciousInstructions(
  filePath: string,
  content: string,
  issues: InstructionFileIssue[]
): void {
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    for (const pattern of SUSPICIOUS_PATTERNS) {
      const match = pattern.exec(lines[i]);
      if (match) {
        addIssue(
          filePath,
          "suspicious-instruction",
          i + 1,
          match[0],
          `Suspicious instruction "${match[0]}" in ${fileName(filePath)} line ${i + 1}`,
          "Review this instruction — it may be a prompt injection attempt",
          issues
        );
        return; // One finding per category per file
      }
    }
  }
}

function addIssue(
  filePath: string,
  issue: InstructionFileIssue["issue"],
  lineNumber: number,
  matchedText: string,
  description: string,
  suggestion: string,
  issues: InstructionFileIssue[]
): void {
  issues.push({
    id: `integrity-${issue}-${filePath}`,
    filePath,
    issue,
    severity: ISSUE_SEVERITY[issue] ?? "info",
    lineNumber,
    matchedText,
    description,
    suggestion,
  });
}

function fileName(path: string): string {
  return path.split("/").pop() ?? path;
}
