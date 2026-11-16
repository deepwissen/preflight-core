import type { InstructionFileIssue } from "../types.js";

/**
 * Skill scope extraction.
 *
 * A Claude Code skill / slash command / subagent declares the tools it may use
 * via `allowed-tools:` in its frontmatter. The agent-config scanner only inspects
 * settings.json-style configs, so these declarations are otherwise invisible.
 * This module parses that declared scope (for display in a skills manifest) and
 * flags over-broad grants (unrestricted shell / all tools) as excessive agency
 * (OWASP LLM06) at the skill level.
 *
 * DECLARED-ONLY: the body prose can instruct the agent beyond these grants, which
 * this does not capture — consistent with detect-and-explain, never certify-safe.
 */

/** A single tool grant from an `allowed-tools` declaration. */
export interface ToolGrant {
  raw: string; // as written, e.g. "Bash(git diff:*)"
  tool: string; // "Bash", "Read", "mcp__x__y", or "*"
  arg: string | null; // "git diff:*" or null when no parenthesised argument
}

/** The declared scope of a skill/command/agent file. */
export interface SkillScope {
  isSkill: boolean; // path looks like a skill/command/agent file
  name: string | null;
  description: string | null;
  declaredTools: boolean; // an allowed-tools key was present
  tools: ToolGrant[];
  broad: boolean; // at least one over-broad grant
  broadGrants: string[]; // the raw grants that are over-broad
}

const SKILL_PATH = /(^|\/)skill\.md$|(^|\/)\.claude\/(skills|commands|agents)\/.*\.md$/i;

/** Skill/command/agent files that can declare a tool scope in frontmatter. */
export function isSkillScopeFile(path: string): boolean {
  return SKILL_PATH.test(path.toLowerCase());
}

/** Extract the leading YAML frontmatter block (--- … ---) as raw text, or null. */
function frontmatterBlock(content: string): string | null {
  const m = /^\uFEFF?\s*---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(content);
  return m ? m[1] : null;
}

/** Read an inline scalar value for `key:` from frontmatter, stripping quotes. */
function scalar(fm: string, key: string): string | null {
  const m = new RegExp(`^[ \\t]*${key}[ \\t]*:[ \\t]*(.*)$`, "im").exec(fm);
  if (!m) return null;
  let v = m[1].trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1);
  }
  return v || null;
}

const ALLOWED_TOOLS_KEY = /^[ \t]*(allowed[-_]?tools)[ \t]*:[ \t]*(.*)$/im;

/**
 * Split a comma-separated grant list, respecting parentheses so args that
 * themselves contain commas (e.g. "Bash(git log --oneline, --stat)") stay one grant.
 */
function splitGrants(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of value) {
    if (ch === "(") depth++;
    else if (ch === ")") depth = Math.max(0, depth - 1);
    if (ch === "," && depth === 0) {
      if (cur.trim()) out.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Parse the allowed-tools value — inline comma list OR a YAML block list. */
function parseAllowedTools(fm: string): { present: boolean; grants: string[] } {
  const m = ALLOWED_TOOLS_KEY.exec(fm);
  if (!m) return { present: false, grants: [] };
  const inline = m[2].trim();
  if (inline && inline !== "|" && inline !== ">" && inline !== "[]") {
    // Inline form: `allowed-tools: Read, Bash(git diff:*)` (also tolerates a
    // bracketed `[Read, Bash(*)]` flow sequence).
    return { present: true, grants: splitGrants(inline.replace(/^\[|\]$/g, "")) };
  }
  // Block form: collect following `- item` lines until the next key / dedent.
  const grants: string[] = [];
  for (const line of fm.slice(m.index + m[0].length).split(/\r?\n/)) {
    const item = /^[ \t]*-[ \t]*(.+)$/.exec(line);
    if (item) grants.push(item[1].trim());
    else if (/^[ \t]*\S/.test(line)) break;
  }
  return { present: true, grants };
}

const GRANT_RE = /^([A-Za-z_][\w-]*|\*)(?:\(([\s\S]*)\))?$/;

function parseGrant(raw: string): ToolGrant | null {
  const m = GRANT_RE.exec(raw.trim());
  if (!m) return null;
  return { raw: raw.trim(), tool: m[1], arg: m[2] !== undefined ? m[2].trim() : null };
}

/**
 * Over-broad = grants all tools (`*`) or unrestricted shell (`Bash`, `Bash(*)`,
 * `Bash(:*)`). A scoped grant like `Bash(git diff:*)` is NOT broad.
 */
function isBroadGrant(g: ToolGrant): boolean {
  if (g.tool === "*") return true;
  if (g.tool === "Bash") return g.arg === null || g.arg === "*" || g.arg === ":*";
  return false;
}

/** Parse a skill/command/agent file's declared tool scope from its frontmatter. */
export function extractSkillScope(path: string, content: string): SkillScope {
  const base: SkillScope = {
    isSkill: false,
    name: null,
    description: null,
    declaredTools: false,
    tools: [],
    broad: false,
    broadGrants: [],
  };
  if (!isSkillScopeFile(path)) return base;
  const fm = frontmatterBlock(content);
  if (fm === null) return { ...base, isSkill: true };

  const { present, grants } = parseAllowedTools(fm);
  const tools = grants
    .map(parseGrant)
    .filter((g): g is ToolGrant => g !== null);
  const broadGrants = tools.filter(isBroadGrant).map((g) => g.raw);
  return {
    isSkill: true,
    name: scalar(fm, "name"),
    description: scalar(fm, "description"),
    declaredTools: present,
    tools,
    broad: broadGrants.length > 0,
    broadGrants,
  };
}

function fileName(path: string): string {
  return path.split("/").pop() ?? path;
}

/** 1-based line of the allowed-tools declaration (for finding location). */
function allowedToolsLine(content: string): number {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (/^[ \t]*allowed[-_]?tools[ \t]*:/i.test(lines[i])) return i + 1;
  }
  return 1;
}

/**
 * Flag a skill/command that declares over-broad tool scope (unrestricted shell or
 * all tools) in its frontmatter — skill-level excessive agency (OWASP LLM06) that
 * the settings.json-scoped agent-config scanner does not cover.
 */
export function scanSkillScope(path: string, content: string): InstructionFileIssue[] {
  const scope = extractSkillScope(path, content);
  if (!scope.isSkill || !scope.broad) return [];
  const line = allowedToolsLine(content);
  const grants = scope.broadGrants.join(", ");
  return [
    {
      id: `agent-broad-command-allow-${path}-${line}`,
      filePath: path,
      issue: "agent-broad-command-allow",
      severity: "error",
      lineNumber: line,
      matchedText: grants,
      description: `Skill grants over-broad tool scope (${grants}) in ${fileName(
        path
      )} — the agent can act well beyond this skill's job`,
      suggestion:
        "Scope allowed-tools to the specific tools/commands the skill needs (e.g. Bash(git diff:*)), not Bash(*) or *",
    },
  ];
}
