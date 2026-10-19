const MAX_FINDINGS_PER_FILE = 10;
const ENTROPY_THRESHOLD = 4.5;
const MIN_ENTROPY_LENGTH = 8;
const MOVE_TO_ENV = "Move to environment variables or a secrets manager before prompting";
const PREFER_SHORT_LIVED = "Non-expiring credential in agent reach — move it to a secrets manager and prefer a short-lived, rotated credential";
// ─── Layer 1: Known Provider Prefixes ────────────────────────────
const PROVIDER_PREFIXES = [
    { id: "aws-access-key", label: "AWS Access Key", pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
    { id: "github-token", label: "GitHub Token", pattern: /gh[porsut]_[a-zA-Z0-9]{36}/ },
    // Only sk_ (secret) and rk_ (restricted) are secrets; pk_ (publishable) is
    // public by design — Stripe ships it in client-side code — so it is NOT flagged.
    { id: "stripe-key", label: "Stripe Key", pattern: /[sr]k_live_[a-zA-Z0-9]{24,}/ },
    { id: "google-api-key", label: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/ },
    { id: "slack-token", label: "Slack Token", pattern: /xox[bpras]-[a-zA-Z0-9-]+/ },
    { id: "openai-key", label: "OpenAI API Key", pattern: /sk-proj-[A-Za-z0-9]{20,}/ },
    { id: "gitlab-token", label: "GitLab Token", pattern: /glpat-[A-Za-z0-9_-]{20,}/ },
    { id: "npm-token", label: "npm Token", pattern: /npm_[A-Za-z0-9]{36}/ },
    {
        id: "private-key-block",
        label: "Private Key",
        pattern: /-----BEGIN[A-Z ]*PRIVATE KEY-----/,
    },
];
// ─── Layer 2: Keyword + Assignment ───────────────────────────────
// Quoted values — works in any language
const KEYWORD_PATTERN = /\b(\w*(?:password|passwd|pwd|pass|secret|token|api_key|apikey|auth_key|private_key|access_key|secret_key|conn_str|connection_string))\s*[:=]>?\s*["'`]([^"'`\n]{1,200})["'`]/i;
// Unquoted values — for YAML, .properties, .ini, .env, TOML, config files
const KEYWORD_UNQUOTED_PATTERN = /\b(\w*(?:password|passwd|pwd|pass|secret|token|api_key|apikey|auth_key|private_key|access_key|secret_key|conn_str|connection_string))\s*[:=]\s*(\S+)\s*$/i;
const UNQUOTED_VALUE_LANGUAGES = new Set([
    "yaml",
    "properties",
    "ini",
    "toml",
    "dotenv",
    "plaintext",
    "shellscript",
    "dockerfile",
    "ansible",
    "spring-boot-properties-yaml",
    "home-assistant",
    "cloudformation",
    "conf",
]);
const PLACEHOLDER_PATTERNS = [
    /^$/,
    /^(changeme|change_me|example|test|dummy|fake|xxx|placeholder|none|null|undefined)$/i,
    /^(TODO|FIXME|CHANGEME|REPLACE_ME)/i,
    /^your[-_]/i,
    /^<.*>$/,
    /^\$\{/,
    /^process\.env\b/,
    /^os\.environ\b/,
    /^ENV\[/,
    /^%\w+%$/,
    /^System\.getenv\b/,
    /^\.\.\./,
    // Templating placeholders: {{var}} / {{${name}}} (mustache/handlebars), ${var}, <%= %>
    /^\{\{.*\}\}$/,
    /^<%=?.*%>$/,
    // Obvious example literals: "oauth2-token-here", "api-key-goes-here", "token_here"
    /[-_](here|goes[-_]here)$/i,
    // GitHub Actions permission values (id-token: write / read / none), not secrets
    /^(read|write)$/i,
];
function isPlaceholder(value) {
    return PLACEHOLDER_PATTERNS.some((p) => p.test(value.trim()));
}
// ─── Layer 4: Connection Strings ─────────────────────────────────
// A connection string is only a *secret* if it actually embeds credentials —
// `://user:pass@host` or a `password=`/`pwd=` query param. A bare
// `jdbc:postgresql://host:5432/db` (Spring's `spring.datasource.url`, etc.) is
// just a host reference, not a credential.
const CONN_CREDS = /:\/\/[^\s/@]*:[^\s/@]+@|[?&](password|passwd|pwd)=[^&\s]+/i;
const CONNECTION_STRING_PATTERNS = [
    {
        id: "connection-string-uri",
        label: "Connection String",
        pattern: /\b(mongodb|postgres|postgresql|mysql|redis|amqp|mssql)\+?\w*:\/\/[^\s"'`]{5,}/i,
        requiresCreds: true,
    },
    {
        id: "connection-string-jdbc",
        label: "JDBC Connection String",
        pattern: /\bjdbc:(postgresql|mysql|sqlserver|oracle):\/\/[^\s"'`]{5,}/i,
        requiresCreds: true,
    },
    {
        id: "connection-string-dotnet",
        label: ".NET Connection String",
        pattern: /Server\s*=\s*[^;]+;.*Password\s*=\s*[^;]+/i,
    },
    {
        // Credentials embedded directly in a URL: scheme://user:password@host
        // (http(s), ftp, redis, amqp, …). Not covered by isNonSecretValue's URL skip
        // because that skip only fires in the entropy layer, which runs later.
        id: "url-embedded-credentials",
        label: "Credentials in URL",
        // Group 1 = the password portion, so we can skip variable interpolations
        // (e.g. https://x-access-token:${GH_TOKEN}@github.com — the standard GitHub
        // Actions idiom, where the "password" is injected from a secret, not literal).
        pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s:/@]+)@[^\s/]+/i,
    },
];
// A credential value that is actually a variable/interpolation, not a literal:
// ${VAR}, $VAR, {{var}}, %VAR%, <...>. Common in CI/templated configs.
function isInterpolation(value) {
    return /^[$%{<]/.test(value) || /\$\{|\{\{/.test(value);
}
// ─── Layer 5: Context Filtering ──────────────────────────────────
const COMMENT_LINE = /^\s*(\/\/|#|\/\*|\*\/?\s|\*\s|<!--|--\s|%\s|;\s)/;
// In config formats (.npmrc, .ini, .properties, .env, YAML, TOML) a leading "//"
// is NOT a comment — e.g. `.npmrc` auth lines start with `//registry.npmjs.org/…`.
// Only "#" and ";" are comments there, so treating "//" as one hid real secrets.
const CONFIG_COMMENT_LINE = /^\s*[#;]/;
// In Markdown/prose, a leading "#" is a heading (and "//"/";" are not comments),
// so only real HTML comments count — otherwise a secret on a heading line is missed.
const MARKDOWN_COMMENT_LINE = /^\s*<!--/;
const TEST_FILE_PATTERN = /\.(test|spec)\.(ts|tsx|js|jsx)$|__tests__\//;
function isConfigFilePath(path, languageId) {
    return (UNQUOTED_VALUE_LANGUAGES.has(languageId) ||
        /\.(ya?ml|properties|ini|toml|env|cfg|conf)$/i.test(path) ||
        /(^|\/)\.(npmrc|netrc|git-credentials)$/i.test(path));
}
function isMarkdownFile(path, languageId) {
    return languageId === "markdown" || /\.(md|markdown|mdx)$/i.test(path);
}
/** The comment style differs by file type; picking the wrong one either misses
 *  secrets (treating a heading/URL as a comment) or scans noise. */
function commentPatternFor(path, languageId) {
    if (isMarkdownFile(path, languageId))
        return MARKDOWN_COMMENT_LINE;
    if (isConfigFilePath(path, languageId))
        return CONFIG_COMMENT_LINE;
    return COMMENT_LINE;
}
function shouldSkipLine(line, commentPattern) {
    return commentPattern.test(line);
}
function shouldSkipFile(path, contentLength) {
    if (contentLength > 100_000)
        return true;
    if (TEST_FILE_PATTERN.test(path))
        return true;
    return false;
}
// Generated / asset files are full of long high-entropy, non-secret tokens
// (SVG path & style data, minified bundles, source maps, lockfile hashes). The
// entropy layer is meaningless there, so skip it for these — the keyword and
// provider layers still run (a real key pasted into any file is still caught).
const ENTROPY_SKIP_FILE = /\.(svg|map)$|\.min\.(js|css)$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.ya?ml)$/i;
function skipEntropyForFile(path) {
    return ENTROPY_SKIP_FILE.test(path);
}
// A keyword value that is a bare alphabetic word (no digits/symbols), a URL, a
// path, or a version is a field echo / identifier / placeholder — not a literal
// credential. Real secrets carry entropy from digits/symbols or are long.
function isNonSecretKeywordValue(value) {
    const v = value.trim();
    return (
    // A short kebab/snake word-chain of letters (no digits/entropy): a field echo
    // or placeholder, not a credential — "token", "apiKey", "access-token",
    // "refresh_token", "my-secret-key". Real tokens carry digits/entropy; capped
    // at 3 segments / 25 chars so multi-word passphrases are still flagged.
    (v.length < 25 && /^[A-Za-z]+([-_][A-Za-z]+){0,2}$/.test(v)) ||
        /^https?:\/\//.test(v) || // a URL assigned to a *_key-ish field
        /^\/[\w-]/.test(v) || // absolute path
        /^\d+(\.\d+)*$/.test(v) // version / number
    );
}
// ─── Layer 3: Shannon Entropy ────────────────────────────────────
export function shannonEntropy(str) {
    if (str.length === 0)
        return 0;
    const freq = new Map();
    for (const ch of str) {
        freq.set(ch, (freq.get(ch) ?? 0) + 1);
    }
    let entropy = 0;
    const len = str.length;
    for (const count of freq.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
const QUOTED_STRING_PATTERN = /["'`]([^"'`\n]{8,200})["'`]/g;
function isNonSecretValue(value) {
    return (/^https?:\/\//.test(value) || // URLs
        /^file:\/\//.test(value) || // file URIs
        /^\/[\w-]/.test(value) || // absolute paths
        /^arn:/.test(value) || // AWS ARNs
        /^[\w.-]+\.\w{2,}\//.test(value) || // registry.io/image, domain/path
        /:\w[\w.-]*$/.test(value) || // image:tag patterns (cr.io/img:v1.2)
        /^\d+\.\d+\.\d+/.test(value) || // version numbers (1.2.3, 10.0.0.1)
        // Subresource-integrity / checksum digests (base64), e.g. "sha256-…", "sha512-…".
        // High-entropy but not secrets — common in lockfiles and <script integrity>.
        /^sha(1|224|256|384|512)-[A-Za-z0-9+/=]+$/i.test(value) ||
        // Data URIs, e.g. "data:image/png;base64,…" — encoded assets, not credentials.
        /^data:[\w.+-]+\/[\w.+-]+/i.test(value) ||
        // Contains whitespace → prose/markup, not a contiguous secret token. Catches
        // structured strings like RDF "@prefix rdf: <http://…> ." that score high on
        // entropy. Keyword-based secrets with spaces are still caught by Layer 2.
        /\s/.test(value) ||
        // Contains CSS/markup/code structural punctuation — SVG path data ("M10,20L…"),
        // inline styles ("fill:#fff;stroke:…"), minified JS/CSS. Real credential tokens
        // are drawn from [A-Za-z0-9_\-+/=.:~] and never contain ; { } < > ( ) or commas.
        /[;{}<>(),]/.test(value) ||
        // Contains a URL/URI scheme anywhere (namespaces, endpoints). Any *credentialed*
        // URL is still flagged separately by the connection-string layer.
        /\w+:\/\//.test(value));
}
// ─── Helpers ─────────────────────────────────────────────────────
function redact(value) {
    if (value.length <= 8)
        return "****";
    return value.slice(0, 4) + "****" + value.slice(-4);
}
function fileName(path) {
    return path.split("/").pop() ?? path;
}
// ─── Credential lifetime classification ──────────────────────────
// Provider-prefix rule IDs whose credential type is static / non-expiring.
const LONG_LIVED_RULE_IDS = new Set([
    "aws-access-key", // AKIA (static IAM); ASIA session tokens handled separately
    "github-token",
    "gitlab-token",
    "npm-token",
    "google-api-key",
    "stripe-key",
    "slack-token",
    "openai-key",
    "private-key-block",
    "connection-string-uri",
    "connection-string-jdbc",
    "connection-string-dotnet",
    "url-embedded-credentials",
]);
const JWT_PATTERN = /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
/** A JWT that carries an `exp` claim is a short-lived token by design. */
function jwtHasExpiry(value) {
    if (!JWT_PATTERN.test(value))
        return false;
    try {
        const b64 = value.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
        const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
        const json = JSON.parse(atob(padded));
        return typeof json.exp === "number";
    }
    catch {
        return false;
    }
}
/**
 * Classify how long-lived a detected credential is. Long-lived/static
 * credentials in agent reach are the higher-risk artefact.
 */
function classifyLifetime(ruleId, value) {
    // Ephemeral by construction.
    if (ruleId === "aws-access-key" && /ASIA[0-9A-Z]{16}/.test(value))
        return "short-lived";
    if (jwtHasExpiry(value))
        return "short-lived";
    if (LONG_LIVED_RULE_IDS.has(ruleId))
        return "long-lived";
    // keyword-secret / high-entropy with no type signal.
    return "unknown";
}
function suggestionFor(lifetime) {
    return lifetime === "long-lived" ? PREFER_SHORT_LIVED : MOVE_TO_ENV;
}
// ─── Main Scanner ────────────────────────────────────────────────
/**
 * Scans the active file's content for hardcoded secrets using 4 detection layers:
 *   Layer 1: Known provider prefixes (AWS, GitHub, Stripe, etc.) — severity: error
 *   Layer 2: Keyword + literal value (password, secret, token, etc.) — severity: warning
 *   Layer 3: Shannon entropy on quoted strings — severity: warning
 *   Layer 4: Connection strings (mongodb://, postgres://, etc.) — severity: warning
 *   Layer 5: Context filtering applied inline (skip comments, test files, placeholders)
 */
export function scanSecrets(context, _partial) {
    const secretFindings = [];
    const wastePatterns = [];
    const file = context.activeFile;
    if (!file?.content)
        return { secretFindings };
    if (shouldSkipFile(file.path, file.content.length))
        return { secretFindings };
    const lines = file.content.split("\n");
    const flaggedLines = new Set();
    const configFile = isConfigFilePath(file.path, file.languageId);
    const commentPattern = commentPatternFor(file.path, file.languageId);
    for (let i = 0; i < lines.length && secretFindings.length < MAX_FINDINGS_PER_FILE; i++) {
        const line = lines[i];
        if (shouldSkipLine(line, commentPattern))
            continue;
        // Layer 1: Provider prefixes
        for (const { id, label, pattern } of PROVIDER_PREFIXES) {
            const match = pattern.exec(line);
            if (match) {
                const lifetime = classifyLifetime(id, match[0]);
                secretFindings.push({
                    id: `${id}-${file.path}-${i + 1}`,
                    filePath: file.path,
                    lineNumber: i + 1,
                    ruleId: id,
                    layer: 1,
                    severity: "error",
                    label,
                    description: `${label} found in ${fileName(file.path)} line ${i + 1}`,
                    matchPreview: redact(match[0]),
                    suggestion: suggestionFor(lifetime),
                    lifetime,
                });
                flaggedLines.add(i);
                break; // One finding per line for Layer 1
            }
        }
        // Layer 2: Keyword + assignment (quoted or unquoted for config files)
        if (!flaggedLines.has(i)) {
            const quotedMatch = KEYWORD_PATTERN.exec(line);
            const kwMatch = quotedMatch ?? (configFile ? KEYWORD_UNQUOTED_PATTERN.exec(line) : null);
            if (kwMatch) {
                const keyName = kwMatch[1];
                const value = kwMatch[2];
                // The field-echo guard (bare word / URL / path / version) applies only to
                // quoted values in code. An unquoted value in a config file (YAML/.env/…)
                // is a real hardcoded secret even when it's a short word.
                const isFieldEcho = quotedMatch !== null && isNonSecretKeywordValue(value);
                // The keyword also appears in prose (`echo "... add as secret:"`) where the
                // unquoted "value" is just a stray quote/punctuation — not credential-shaped.
                const stripped = value.replace(/^["'`]+|["'`]+$/g, "").trim();
                const isProse = quotedMatch === null && (stripped.length < 3 || !/[A-Za-z0-9]/.test(stripped));
                const isVariable = isInterpolation(value);
                // The keyword is a segment of an AWS ARN (…:secretsmanager:…:secret:plt/…),
                // i.e. a resource identifier, not an assignment — not a secret.
                const inArn = /\barn:[a-z0-9-]*:/i.test(line.slice(0, kwMatch.index));
                if (!isPlaceholder(value) && !isFieldEcho && !isProse && !isVariable && !inArn) {
                    const lifetime = classifyLifetime("keyword-secret", value);
                    secretFindings.push({
                        id: `keyword-${keyName}-${file.path}-${i + 1}`,
                        filePath: file.path,
                        lineNumber: i + 1,
                        ruleId: "keyword-secret",
                        layer: 2,
                        severity: "warning",
                        label: "Hardcoded secret",
                        description: `Hardcoded ${keyName} in ${fileName(file.path)} line ${i + 1}`,
                        matchPreview: `${keyName} = "${redact(value)}"`,
                        suggestion: suggestionFor(lifetime),
                        lifetime,
                    });
                    flaggedLines.add(i);
                }
            }
        }
        // Layer 4: Connection strings
        if (!flaggedLines.has(i)) {
            for (const { id, label, pattern, requiresCreds } of CONNECTION_STRING_PATTERNS) {
                const csMatch = pattern.exec(line);
                if (csMatch) {
                    // A connection URI without embedded credentials is just a host
                    // reference (e.g. Spring's spring.datasource.url), not a secret.
                    if (requiresCreds && !CONN_CREDS.test(csMatch[0])) {
                        continue;
                    }
                    // URL creds whose password is a variable (${GH_TOKEN}, {{var}}, …) are
                    // not a literal secret — skip (standard CI/templated pattern).
                    if (id === "url-embedded-credentials" && csMatch[1] && isInterpolation(csMatch[1])) {
                        continue;
                    }
                    const lifetime = classifyLifetime(id, csMatch[0]);
                    secretFindings.push({
                        id: `${id}-${file.path}-${i + 1}`,
                        filePath: file.path,
                        lineNumber: i + 1,
                        ruleId: id,
                        layer: 4,
                        severity: "warning",
                        label,
                        description: `${label} in ${fileName(file.path)} line ${i + 1}`,
                        matchPreview: redact(csMatch[0]),
                        suggestion: suggestionFor(lifetime),
                        lifetime,
                    });
                    flaggedLines.add(i);
                    break;
                }
            }
        }
    }
    // Layer 3: Entropy scan on quoted strings (skip lines already flagged).
    // Skipped wholesale for generated/asset files, which are entropy noise.
    for (let i = 0; i < lines.length &&
        secretFindings.length < MAX_FINDINGS_PER_FILE &&
        !skipEntropyForFile(file.path); i++) {
        if (flaggedLines.has(i))
            continue;
        if (shouldSkipLine(lines[i], commentPattern))
            continue;
        QUOTED_STRING_PATTERN.lastIndex = 0;
        let qMatch;
        while ((qMatch = QUOTED_STRING_PATTERN.exec(lines[i])) !== null &&
            secretFindings.length < MAX_FINDINGS_PER_FILE) {
            const value = qMatch[1];
            if (isNonSecretValue(value))
                continue;
            if (isPlaceholder(value))
                continue;
            if (value.length < MIN_ENTROPY_LENGTH)
                continue;
            const entropy = shannonEntropy(value);
            if (entropy > ENTROPY_THRESHOLD) {
                const lifetime = classifyLifetime("high-entropy", value);
                secretFindings.push({
                    id: `high-entropy-${file.path}-${i + 1}`,
                    filePath: file.path,
                    lineNumber: i + 1,
                    ruleId: "high-entropy",
                    layer: 3,
                    severity: "warning",
                    label: "High-entropy string",
                    description: `Potential secret (entropy ${entropy.toFixed(1)}) in ${fileName(file.path)} line ${i + 1}`,
                    matchPreview: redact(value),
                    suggestion: suggestionFor(lifetime),
                    lifetime,
                });
                flaggedLines.add(i);
                break; // One entropy finding per line
            }
        }
    }
    // Generate waste pattern if any secrets found
    if (secretFindings.length > 0) {
        wastePatterns.push({
            ruleId: "secret-in-content",
            source: file.path,
            description: `${secretFindings.length} potential secret(s) found in ${fileName(file.path)}`,
            severity: "warning",
            suggestion: "Move secrets to environment variables or a secrets manager before prompting",
        });
    }
    return { secretFindings, wastePatterns };
}
//# sourceMappingURL=secret-scanner.js.map