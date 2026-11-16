const SKILL_PATH = /(^|\/)skill\.md$|(^|\/)\.claude\/(skills|commands|agents)\/.*\.md$/i;
/** Skill/command/agent files that can declare a tool scope in frontmatter. */
export function isSkillScopeFile(path) {
    return SKILL_PATH.test(path.toLowerCase());
}
/** Split a file into its leading YAML frontmatter block (--- … ---) and the body. */
function splitFrontmatter(content) {
    const m = /^\uFEFF?\s*---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(content);
    if (!m)
        return { fm: null, body: content };
    return { fm: m[1], body: content.slice(m.index + m[0].length) };
}
/** Read an inline scalar value for `key:` from frontmatter, stripping quotes. */
function scalar(fm, key) {
    const m = new RegExp(`^[ \\t]*${key}[ \\t]*:[ \\t]*(.*)$`, "im").exec(fm);
    if (!m)
        return null;
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
function splitGrants(value) {
    const out = [];
    let depth = 0;
    let cur = "";
    for (const ch of value) {
        if (ch === "(")
            depth++;
        else if (ch === ")")
            depth = Math.max(0, depth - 1);
        if (ch === "," && depth === 0) {
            if (cur.trim())
                out.push(cur.trim());
            cur = "";
        }
        else {
            cur += ch;
        }
    }
    if (cur.trim())
        out.push(cur.trim());
    return out;
}
/** Parse the allowed-tools value — inline comma list OR a YAML block list. */
function parseAllowedTools(fm) {
    const m = ALLOWED_TOOLS_KEY.exec(fm);
    if (!m)
        return { present: false, grants: [] };
    const inline = m[2].trim();
    if (inline && inline !== "|" && inline !== ">" && inline !== "[]") {
        // Inline form: `allowed-tools: Read, Bash(git diff:*)` (also tolerates a
        // bracketed `[Read, Bash(*)]` flow sequence).
        return { present: true, grants: splitGrants(inline.replace(/^\[|\]$/g, "")) };
    }
    // Block form: collect following `- item` lines until the next key / dedent.
    const grants = [];
    for (const line of fm.slice(m.index + m[0].length).split(/\r?\n/)) {
        const item = /^[ \t]*-[ \t]*(.+)$/.exec(line);
        if (item)
            grants.push(item[1].trim());
        else if (/^[ \t]*\S/.test(line))
            break;
    }
    return { present: true, grants };
}
const GRANT_RE = /^([A-Za-z_][\w-]*|\*)(?:\(([\s\S]*)\))?$/;
function parseGrant(raw) {
    const m = GRANT_RE.exec(raw.trim());
    if (!m)
        return null;
    return { raw: raw.trim(), tool: m[1], arg: m[2] !== undefined ? m[2].trim() : null };
}
/**
 * Over-broad = grants all tools (`*`) or unrestricted shell (`Bash`, `Bash(*)`,
 * `Bash(:*)`). A scoped grant like `Bash(git diff:*)` is NOT broad.
 */
function isBroadGrant(g) {
    if (g.tool === "*")
        return true;
    if (g.tool === "Bash")
        return g.arg === null || g.arg === "*" || g.arg === ":*";
    return false;
}
/** The MCP server a grant reaches, parsed from an `mcp__<server>__<tool>` name. */
function mcpServerOf(tool) {
    if (!tool.startsWith("mcp__"))
        return null;
    const rest = tool.slice(5);
    const i = rest.indexOf("__");
    return (i === -1 ? rest : rest.slice(0, i)) || null;
}
// Scripts the body instructs the agent to run — via an interpreter
// (`bash scripts/x.sh`, `python ./setup.py`) or a direct relative path (`./run.sh`).
// Conservative by design (manifest metadata, not a finding); a bundled-file walk by
// the CLI enumerates what actually ships more precisely.
const SCRIPT_EXT = "(?:sh|bash|zsh|py|rb|pl|js|cjs|mjs|ts)";
const INTERP_REF = new RegExp(`\\b(?:bash|sh|zsh|python3?|ruby|perl|node|npx|deno)\\s+((?:\\.{0,2}/)?[\\w./-]+\\.${SCRIPT_EXT})\\b`, "g");
const PATH_REF = new RegExp(`(?:^|[\\s\`'"(])(\\.{1,2}/[\\w./-]*\\.${SCRIPT_EXT})\\b`, "g");
function extractScriptRefs(body) {
    const found = new Set();
    for (const re of [INTERP_REF, PATH_REF]) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(body)) !== null)
            found.add(m[1]);
    }
    return [...found];
}
/** Parse a skill/command/agent file's declared tool scope from its frontmatter. */
export function extractSkillScope(path, content) {
    const base = {
        isSkill: false,
        name: null,
        description: null,
        declaredTools: false,
        tools: [],
        broad: false,
        broadGrants: [],
        mcpServers: [],
        referencedScripts: [],
    };
    if (!isSkillScopeFile(path))
        return base;
    const { fm, body } = splitFrontmatter(content);
    const referencedScripts = extractScriptRefs(body);
    if (fm === null)
        return { ...base, isSkill: true, referencedScripts };
    const { present, grants } = parseAllowedTools(fm);
    const tools = grants.map(parseGrant).filter((g) => g !== null);
    const broadGrants = tools.filter(isBroadGrant).map((g) => g.raw);
    const mcpServers = [
        ...new Set(tools.map((t) => mcpServerOf(t.tool)).filter((s) => s !== null)),
    ];
    return {
        isSkill: true,
        name: scalar(fm, "name"),
        description: scalar(fm, "description"),
        declaredTools: present,
        tools,
        broad: broadGrants.length > 0,
        broadGrants,
        mcpServers,
        referencedScripts,
    };
}
function fileName(path) {
    return path.split("/").pop() ?? path;
}
/** 1-based line of the allowed-tools declaration (for finding location). */
function allowedToolsLine(content) {
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
        if (/^[ \t]*allowed[-_]?tools[ \t]*:/i.test(lines[i]))
            return i + 1;
    }
    return 1;
}
/**
 * Flag a skill/command that declares over-broad tool scope (unrestricted shell or
 * all tools) in its frontmatter — skill-level excessive agency (OWASP LLM06) that
 * the settings.json-scoped agent-config scanner does not cover.
 */
export function scanSkillScope(path, content) {
    const scope = extractSkillScope(path, content);
    if (!scope.isSkill || !scope.broad)
        return [];
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
            description: `Skill grants over-broad tool scope (${grants}) in ${fileName(path)} — the agent can act well beyond this skill's job`,
            suggestion: "Scope allowed-tools to the specific tools/commands the skill needs (e.g. Bash(git diff:*)), not Bash(*) or *",
        },
    ];
}
//# sourceMappingURL=skill-scope.js.map