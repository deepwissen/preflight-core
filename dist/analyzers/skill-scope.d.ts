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
    raw: string;
    tool: string;
    arg: string | null;
}
/** The declared scope of a skill/command/agent file. */
export interface SkillScope {
    isSkill: boolean;
    name: string | null;
    description: string | null;
    declaredTools: boolean;
    tools: ToolGrant[];
    broad: boolean;
    broadGrants: string[];
    mcpServers: string[];
    referencedScripts: string[];
}
/** Skill/command/agent files that can declare a tool scope in frontmatter. */
export declare function isSkillScopeFile(path: string): boolean;
/** Parse a skill/command/agent file's declared tool scope from its frontmatter. */
export declare function extractSkillScope(path: string, content: string): SkillScope;
/**
 * Flag a skill/command that declares over-broad tool scope (unrestricted shell or
 * all tools) in its frontmatter — skill-level excessive agency (OWASP LLM06) that
 * the settings.json-scoped agent-config scanner does not cover.
 */
export declare function scanSkillScope(path: string, content: string): InstructionFileIssue[];
//# sourceMappingURL=skill-scope.d.ts.map