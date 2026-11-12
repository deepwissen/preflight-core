import type {
  AnalysisResult,
  ContextSnapshot,
  SecretFinding,
  SecretLifetime,
  WastePattern,
} from "../types.js";

// Per-file ceiling — a backstop against a pathological file flooding output, NOT
// a feature. The CredData benchmark showed a cap of 50 silently dropped real
// secrets and halved recall (22% vs 50% with it lifted); raised to 1000 so no
// real file is truncated. Secret-packed files report everything they contain.
const MAX_FINDINGS_PER_FILE = 1000;
const ENTROPY_THRESHOLD = 4.5;
const MIN_ENTROPY_LENGTH = 8;
const MOVE_TO_ENV = "Move to environment variables or a secrets manager before prompting";
const PREFER_SHORT_LIVED =
  "Non-expiring credential in agent reach — move it to a secrets manager and prefer a short-lived, rotated credential";

// ─── Layer 1: Known Provider Prefixes ────────────────────────────

const PROVIDER_PREFIXES: Array<{ id: string; label: string; pattern: RegExp }> = [
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
  // JSON Web Token: header.payload.signature, header & payload base64url of JSON
  // starting `{"` → `eyJ`. The `eyJ…eyJ…` double structure is essentially unique
  // to JWTs, so this is high-precision and catches bare tokens and `Bearer eyJ…`
  // (which the quoted-string entropy layer never sees).
  {
    id: "jwt",
    label: "JSON Web Token",
    pattern: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/,
  },
];

// ─── Layer 2: Keyword + Assignment ───────────────────────────────

// Quoted values — works in any language. Bare `key` catches app_key/encryption_key/
// signing_key/appKey (missed before); English `-key` words (monkey, hockey) and
// public keys are filtered after the match by isEnglishKeyWord / isPublicKeyField.
const KEYWORD_PATTERN =
  /\b(\w*(?:password|passwd|pwd|pass|secret|token|api_key|apikey|auth_key|private_key|access_key|secret_key|key|conn_str|connection_string))\s*[:=]>?\s*["'`]([^"'`\n]{1,200})["'`]/i;

// Unquoted values — for YAML, .properties, .ini, .env, TOML, config files
const KEYWORD_UNQUOTED_PATTERN =
  /\b(\w*(?:password|passwd|pwd|pass|secret|token|api_key|apikey|auth_key|private_key|access_key|secret_key|key|conn_str|connection_string))\s*[:=]\s*(\S+)\s*$/i;

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
  /^(changeme|change_me|changeit|example|test|dummy|fake|xxx|placeholder|none|null|undefined)$/i,
  // Trivial default values (MYSQL_ROOT_PASSWORD: root) — defaults, not secrets.
  /^(root|admin|administrator|guest|user|username|default|password|secret|enabled?)$/i,
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
  // Boolean / flag values on a secret-named field (revoke_access_token: true) are
  // config switches, not credentials.
  /^(true|false|yes|no|on|off|enabled?|disabled?)$/i,
  // A plain integer (token_ttl: 3600, max_retries: 5) is config, never a secret.
  /^\d+$/,
];

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((p) => p.test(value.trim()));
}

// ─── Layer 4: Connection Strings ─────────────────────────────────

// A connection string is only a *secret* if it actually embeds credentials —
// `://user:pass@host` or a `password=`/`pwd=` query param. A bare
// `jdbc:postgresql://host:5432/db` (Spring's `spring.datasource.url`, etc.) is
// just a host reference, not a credential.
const CONN_CREDS = /:\/\/[^\s/@]*:[^\s/@]+@|[?&](password|passwd|pwd)=[^&\s]+/i;

const CONNECTION_STRING_PATTERNS: Array<{
  id: string;
  label: string;
  pattern: RegExp;
  requiresCreds?: boolean;
}> = [
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
function isInterpolation(value: string): boolean {
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

function isConfigFilePath(path: string, languageId: string): boolean {
  return (
    UNQUOTED_VALUE_LANGUAGES.has(languageId) ||
    /\.(ya?ml|properties|ini|toml|env|cfg|conf)$/i.test(path) ||
    /(^|\/)\.(npmrc|netrc|git-credentials)$/i.test(path)
  );
}

function isMarkdownFile(path: string, languageId: string): boolean {
  return languageId === "markdown" || /\.(md|markdown|mdx)$/i.test(path);
}

/** The comment style differs by file type; picking the wrong one either misses
 *  secrets (treating a heading/URL as a comment) or scans noise. */
function commentPatternFor(path: string, languageId: string): RegExp {
  if (isMarkdownFile(path, languageId)) return MARKDOWN_COMMENT_LINE;
  if (isConfigFilePath(path, languageId)) return CONFIG_COMMENT_LINE;
  return COMMENT_LINE;
}

function shouldSkipLine(line: string, commentPattern: RegExp): boolean {
  return commentPattern.test(line);
}

// Files larger than this are skipped entirely (returns no findings). Raised from
// 100 KB to 1 MB after the CredData benchmark showed the old cap silently hid ~32%
// of real secrets — it now matches the vet CLI's own 1 MB byte cap, so a file the
// CLI reads is a file the scanner actually scans. Callers that skip a file for
// size MUST surface that (a silent skip reads as "clean", which is false).
const MAX_SCAN_CHARS = 1_000_000;

function shouldSkipFile(path: string, contentLength: number): boolean {
  if (contentLength > MAX_SCAN_CHARS) return true;
  if (TEST_FILE_PATTERN.test(path)) return true;
  return false;
}

// Generated / asset files are full of long high-entropy, non-secret tokens
// (SVG path & style data, minified bundles, source maps, lockfile hashes). The
// entropy layer is meaningless there, so skip it for these — the keyword and
// provider layers still run (a real key pasted into any file is still caught).
const ENTROPY_SKIP_FILE =
  /\.(svg|map|html?|classpath|project|iml)$|\.min\.(js|css)$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.ya?ml)$|(^|\/)\.idea\/|(^|\/)\.settings\//i;

function skipEntropyForFile(path: string): boolean {
  return ENTROPY_SKIP_FILE.test(path);
}

// A keyword value that is a bare alphabetic word (no digits/symbols), a URL, a
// path, or a version is a field echo / identifier / placeholder — not a literal
// credential. Real secrets carry entropy from digits/symbols or are long.
function isNonSecretKeywordValue(value: string): boolean {
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

// Identifier segments that mean the *value* is just echoing a credential field
// name (`token: access_token`, `api_key: api_key`), not a real secret.
const SECRET_WORD_SEGMENTS = new Set([
  "password",
  "passwd",
  "pwd",
  "pass",
  "secret",
  "token",
  "key",
  "auth",
  "credential",
  "cred",
]);

// A field echo in an *unquoted* config value: the value is a pure letter
// identifier (no digits/entropy, ≤3 segments) whose own words name a credential
// — `access_token`, `refresh_token`, `api_key`, `clientSecret`, `TOKEN`. Unlike
// a bare non-keyword word (`vale`, which is a real — if weak — unquoted secret),
// echoing the field name carries no secret. Narrow on purpose so low-entropy
// real values aren't silently dropped.
function isKeywordEchoValue(value: string): boolean {
  const v = value.trim();
  if (v.length >= 25 || !/^[A-Za-z]+([-_][A-Za-z]+){0,2}$/.test(v)) return false;
  // Split on separators AND camelCase boundaries: access_token, accessToken,
  // clientSecret all become ["...","token"/"secret"/"key"].
  const words = v
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[-_ ]+/);
  if (words.some((w) => SECRET_WORD_SEGMENTS.has(w))) return true;
  // Glued all-lowercase compounds with no boundary to split on: apikey, …
  return /(apikey|accesstoken|refreshtoken|authtoken|secretkey|accesskey|privatekey)/.test(
    v.toLowerCase()
  );
}

// RFC 2606 reserved *documentation* domains only — example.com/.org/.net/.edu and
// the .test / .invalid TLDs. Credentials pointing here are examples, not endpoints.
// Deliberately NOT localhost / loopback / .local / real services: CredData labels
// `user:pass@localhost` as a real secret, and a key on sentry.io is a real service.
const DOC_HOST = /(^|\.)(example\.(com|org|net|edu)|test|invalid)$/i;

/** The host portion of a URI/connection string that embeds credentials (the
 *  hostname run right after `@`). Restricted to hostname characters so a trailing
 *  quote/port/path doesn't contaminate it. Empty if there's no `user:pass@host`. */
function hostFromCreds(match: string): string {
  const m = match.match(/@([A-Za-z0-9.-]+)/);
  return m ? m[1] : "";
}

// An all-UPPER screaming-snake identifier (≥1 underscore) assigned as a value is
// an env-var *name* being referenced, not a literal secret — `X = "GCM_AZREPOS_SP_SECRET"`.
// Real keys aren't pure [A-Z0-9_] identifiers (and AWS keys have no underscore).
function isEnvVarNameValue(value: string): boolean {
  const v = value.trim();
  return v.length <= 60 && /^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$/.test(v);
}

// A near-monotonic character run (ABC…XYZ, 0123456789…, abcdef…). Scores high
// Shannon entropy (uniform distribution) but is an obvious filler, not a secret.
function isSequentialRun(value: string): boolean {
  if (value.length < 8) return false;
  let adjacent = 0;
  for (let i = 1; i < value.length; i++) {
    const d = value.charCodeAt(i) - value.charCodeAt(i - 1);
    if (d === 1 || d === -1) adjacent++;
  }
  return adjacent / (value.length - 1) >= 0.8;
}

// A .NET assembly `PublicKeyToken` is a public identity token (like a Stripe
// publishable key), not a secret — e.g. publicKeyToken="b77a5c561934e089".
function isPublicKeyTokenField(keyName: string): boolean {
  return /publickeytoken/i.test(keyName.replace(/[-_]/g, ""));
}

// The bare `key` keyword matches any field ending in "key" — including English
// words where "key" is glued to letters (monkey, donkey, turkey, whiskey, hockey,
// turnkey). A real key field has "key" as its own segment: a non-letter before it
// (app_key, api-key, MY_KEY, bare key) or a camelCase boundary (appKey). This flags
// the English words only; `app_key` etc. and the explicit keywords are unaffected.
function isEnglishKeyWord(keyName: string): boolean {
  return /[a-z]key$/i.test(keyName) && !/[a-z]Key$/.test(keyName);
}

// A public key / token is published by design, not a secret (public_key, pubkey,
// publicKey, public-token).
function isPublicKeyField(keyName: string): boolean {
  return /^pub(lic)?[_-]?(key|token)s?$/i.test(keyName);
}

// A dotted identifier / property path used as a value — an i18n key or config
// reference (`home.title`, `app.module.name`), not a credential. Purely alphabetic
// segments only, so anything with digits/entropy (real keys, JWTs) is unaffected.
function isDottedIdentifierValue(value: string): boolean {
  const v = value.trim();
  return v.length < 60 && /^[A-Za-z]+(\.[A-Za-z]+)+$/.test(v);
}

// A field whose name marks it as a test fixture / mock / expected value
// (MOCK_ACCESS_TOKEN, expectedPassword, testApiKey) — not a live credential.
// Splits on separators AND camelCase so the marker is matched as a whole segment
// (so `latest_token`/`contest_key` are NOT caught).
const TEST_FIXTURE_WORDS = /^(mock|test|expected|sample|fake|dummy|stub|fixture|demo)$/;
function isTestFixtureField(keyName: string): boolean {
  return keyName
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[-_ ]+/)
    .some((seg) => TEST_FIXTURE_WORDS.test(seg));
}

// A multi-word camelCase/PascalCase identifier with no digits — a code constant
// or enum name (`keyEquivalentModifierMask`), not a secret. Requires ≥2 case
// transitions so an all-lowercase passphrase (`correcthorsebattery`) or a single
// capitalized word (`MyPassword`) is still flagged. Real keys carry digits/entropy.
function isCodeIdentifierValue(value: string): boolean {
  const v = value.trim();
  return /^[A-Za-z]+$/.test(v) && (v.match(/[a-z][A-Z]/g) ?? []).length >= 2;
}

// HTTP Authorization header credentials — `Authorization: Basic|Bearer|NTLM <cred>`.
// A large class of real secrets (CredData) that the keyword/provider layers miss.
// Variable tokens (${T}, <token>, $VAR) are excluded by the credential charset,
// which admits only base64url characters. Group 1 = scheme, group 2 = credential.
const AUTH_HEADER =
  /\b(?:proxy-)?authorization\s*[:=]\s*["'`]?\s*(basic|bearer|ntlm|negotiate)\s+([A-Za-z0-9+/=._~-]{8,})/i;

// Decode a base64 Basic credential; returns the `user:pass` string, or null if it
// isn't valid base64 / doesn't decode to text. Used to confirm a real Basic header
// (decodes to `user:pass`) and reject random base64 that merely looks like one.
function decodeBasic(b64: string): string | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;
  try {
    const s =
      typeof atob === "function"
        ? atob(b64)
        : // eslint-disable-next-line no-undef
          Buffer.from(b64, "base64").toString("latin1");
    return /^[\x20-\x7e]*$/.test(s) ? s : null; // printable ASCII only
  } catch {
    return null;
  }
}

// ─── Layer 3: Shannon Entropy ────────────────────────────────────

export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
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

function isNonSecretValue(value: string): boolean {
  return (
    /^https?:\/\//.test(value) || // URLs
    /^file:\/\//.test(value) || // file URIs
    /^\/[\w-]/.test(value) || // absolute paths
    // Windows paths: drive-letter (C:\…), UNC (\\server\…), or any value with a
    // backslash separator (.pdb/.dll build paths). Secrets are drawn from
    // [A-Za-z0-9_\-+/=.:~] and never contain a backslash — common entropy noise.
    /^[a-z]:[\\/]/i.test(value) ||
    /\\/.test(value) ||
    // Relative / home-anchored paths: ./x, ../a/b, ~/dir. A filesystem path is
    // word segments, not a contiguous token — but a long one (../Mend_And_Fortify/
    // Fortify/fortify-emrg-viewgen-scr-Svcs) can score high entropy and be mistaken
    // for a secret.
    /^(\.{1,2}|~)[\\/]/.test(value) ||
    // Bare multi-segment path (a/b/c): 3+ segments that are all plain file/dir
    // names (word chars, dot, dash, tilde — no base64 +/= noise). A single-slash
    // value is left to the entropy check (could be a base64 token with one "/").
    (value.split(/[\\/]/).length >= 3 && value.split(/[\\/]/).every((s) => /^[\w.~-]*$/.test(s))) ||
    // Variable-rooted path: $PROJECT_DIR$/…, $HOME/…, ${VAR}/…, %APPDATA%\… — an
    // IDE/shell path macro (JetBrains .idea, Eclipse), never a literal secret.
    // (Does not match bcrypt/argon2 "$2b$…" — no path separator follows the macro.)
    /^(\$\{?\w+\}?\$?|%\w+%)[\\/]/.test(value) ||
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
    /\w+:\/\//.test(value)
  );
}

// ─── Helpers ─────────────────────────────────────────────────────

function redact(value: string): string {
  if (value.length <= 8) return "****";
  return value.slice(0, 4) + "****" + value.slice(-4);
}

function fileName(path: string): string {
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
function jwtHasExpiry(value: string): boolean {
  if (!JWT_PATTERN.test(value)) return false;
  try {
    const b64 = value.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = JSON.parse(atob(padded)) as Record<string, unknown>;
    return typeof json.exp === "number";
  } catch {
    return false;
  }
}

/**
 * Classify how long-lived a detected credential is. Long-lived/static
 * credentials in agent reach are the higher-risk artefact.
 */
function classifyLifetime(ruleId: string, value: string): SecretLifetime {
  // Ephemeral by construction.
  if (ruleId === "aws-access-key" && /ASIA[0-9A-Z]{16}/.test(value)) return "short-lived";
  if (jwtHasExpiry(value)) return "short-lived";

  if (LONG_LIVED_RULE_IDS.has(ruleId)) return "long-lived";

  // keyword-secret / high-entropy with no type signal.
  return "unknown";
}

function suggestionFor(lifetime: SecretLifetime): string {
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
export function scanSecrets(
  context: ContextSnapshot,
  _partial: Partial<AnalysisResult>
): Partial<AnalysisResult> {
  const secretFindings: SecretFinding[] = [];
  const wastePatterns: WastePattern[] = [];

  const file = context.activeFile;
  if (!file?.content) return { secretFindings };
  if (shouldSkipFile(file.path, file.content.length)) return { secretFindings };

  const lines = file.content.split("\n");
  const flaggedLines = new Set<number>();
  const configFile = isConfigFilePath(file.path, file.languageId);
  const commentPattern = commentPatternFor(file.path, file.languageId);

  for (let i = 0; i < lines.length && secretFindings.length < MAX_FINDINGS_PER_FILE; i++) {
    const line = lines[i];
    if (shouldSkipLine(line, commentPattern)) continue;

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

    // Layer 1b: Authorization header credentials (Basic/Bearer/NTLM). Runs after
    // Layer 1 so a `Bearer eyJ…` JWT is attributed to the jwt rule, not double-flagged.
    if (!flaggedLines.has(i)) {
      const am = AUTH_HEADER.exec(line);
      if (am) {
        const scheme = am[1].toLowerCase();
        const cred = am[2];
        let detected = !isPlaceholder(cred) && !isEnvVarNameValue(cred) && !isInterpolation(cred);
        let label = "Authorization credential";
        if (detected && scheme === "basic") {
          const decoded = decodeBasic(cred);
          detected = decoded !== null && decoded.includes(":"); // real Basic → user:pass
          label = "Basic Authorization credential";
        } else if (detected && scheme === "bearer") {
          detected = cred.length >= 16; // opaque bearer token (JWTs already handled)
          label = "Bearer token in Authorization header";
        } else if (detected) {
          detected = cred.length >= 16;
          label = `${scheme.toUpperCase()} Authorization credential`;
        }
        if (detected) {
          const lifetime = classifyLifetime(`auth-header-${scheme}`, cred);
          secretFindings.push({
            id: `auth-header-${scheme}-${file.path}-${i + 1}`,
            filePath: file.path,
            lineNumber: i + 1,
            ruleId: `auth-header-${scheme}`,
            layer: 1,
            severity: "warning",
            label,
            description: `${label} in ${fileName(file.path)} line ${i + 1}`,
            matchPreview: redact(cred),
            suggestion: suggestionFor(lifetime),
            lifetime,
          });
          flaggedLines.add(i);
        }
      }
    }

    // Layer 2: Keyword + assignment (quoted or unquoted for config files)
    if (!flaggedLines.has(i)) {
      const quotedMatch = KEYWORD_PATTERN.exec(line);
      const kwMatch = quotedMatch ?? (configFile ? KEYWORD_UNQUOTED_PATTERN.exec(line) : null);
      if (kwMatch) {
        const keyName = kwMatch[1];
        let value = kwMatch[2];
        // The keyword is a URL *query parameter* (…://host?token=…&client_id=…),
        // not a config assignment. The unquoted pattern greedily grabs the rest of
        // the query string ("access_token&client_id=abc") as the value; bound it to
        // the actual parameter (terminate at & / # / whitespace) and strip a stray
        // closing quote so the real value is what gets judged below. A real secret
        // in a query string (?api_key=<entropy>) still fails the echo/placeholder
        // guards and is flagged; a known provider key is already caught by Layer 1.
        const inUrl = quotedMatch === null && /:\/\//.test(line.slice(0, kwMatch.index));
        if (inUrl) value = value.split(/[&#\s]/)[0].replace(/^["'`]+|["'`]+$/g, "");
        // The field-echo guard (bare word / URL / path / version) applies to quoted
        // values in code. Unquoted config values are real secrets even when short
        // (`ml_ref_password: vale`), EXCEPT when the value just echoes a credential
        // field name (`token: access_token`) — that carries no secret.
        const isFieldEcho =
          (quotedMatch !== null && isNonSecretKeywordValue(value)) ||
          (quotedMatch === null && isKeywordEchoValue(value));
        // The keyword also appears in prose (`echo "... add as secret:"`) where the
        // unquoted "value" is just a stray quote/punctuation — not credential-shaped.
        const stripped = value.replace(/^["'`]+|["'`]+$/g, "").trim();
        const isProse =
          quotedMatch === null && (stripped.length < 3 || !/[A-Za-z0-9]/.test(stripped));
        const isVariable = isInterpolation(value);
        // The keyword is a segment of an AWS ARN (…:secretsmanager:…:secret:plt/…),
        // i.e. a resource identifier, not an assignment — not a secret.
        const inArn = /\barn:[a-z0-9-]*:/i.test(line.slice(0, kwMatch.index));
        // The unquoted value is a code expression, not a literal — e.g. a C/C++
        // parser assignment `cur_token = yyextra->lookahead_token;`, `SECRET = 641,`,
        // `token = tokens[i];`. Code punctuation (-> :: ; () [] {} <> or a trailing
        // comma) never appears in a credential. (Unquoted path only; base64 secrets
        // using / + = are unaffected.)
        const isCodeExpr = quotedMatch === null && /->|::|[;(){}[\]<>]|,\s*$/.test(value);
        // .NET PublicKeyToken is a public identity token; a screaming-snake value is
        // an env-var *name* reference, not a literal secret (CredData false alarms).
        const isPublicToken = isPublicKeyTokenField(keyName);
        const isEnvRef = isEnvVarNameValue(value);
        // The bare `key` keyword also matches English `-key` words (monkey, hockey)
        // and public-key fields — neither is a secret.
        const isNonKeyField = isEnglishKeyWord(keyName) || isPublicKeyField(keyName);
        // A dotted property path / i18n key as the value (`key = "home.title"`).
        const isDottedId = isDottedIdentifierValue(value);
        // A value containing whitespace is prose/a sentence, not a contiguous
        // credential token ("Failed to retrieve the generated key.", "Test Secret").
        const hasWhitespace = /\s/.test(value);
        // The field is a test fixture / mock (MOCK_ACCESS_TOKEN, expectedPassword).
        const isTestFixture = isTestFixtureField(keyName);
        // The value is a multi-word code identifier (keyEquivalentModifierMask).
        const isCodeIdent = isCodeIdentifierValue(value);
        // Password-family fields stay permissive (weak real passwords are short and
        // low-entropy, and vet leads gitleaks here). For key/token/secret/api fields,
        // require a credential-shaped value: ≥8 chars (gitleaks' floor) and not a
        // bare primitive type name (Go struct tags `key:"uint32"`). This cuts the
        // short/structural keyword false alarms without touching passwords.
        const isPwdField = /pass|pwd/i.test(keyName);
        const tooShort = !isPwdField && value.trim().length < 8;
        const isPrimitiveType =
          /^(u?int(8|16|32|64)?|float(32|64)?|string|bool(ean)?|byte|rune|char|double|long|short|object|void|any|date(time)?|guid|uuid)$/i.test(
            value.trim()
          );
        if (
          !isPlaceholder(value) &&
          !isFieldEcho &&
          !isProse &&
          !isVariable &&
          !inArn &&
          !isCodeExpr &&
          !isPublicToken &&
          !isEnvRef &&
          !isNonKeyField &&
          !isDottedId &&
          !hasWhitespace &&
          !isTestFixture &&
          !isCodeIdent &&
          !tooShort &&
          !isPrimitiveType
        ) {
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
          // Credentials pointing at a reserved / documentation host (example.com,
          // localhost, …) are examples, not real endpoints — skip (CredData FPs).
          const credHost = hostFromCreds(csMatch[0]);
          if (credHost && DOC_HOST.test(credHost)) {
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
  for (
    let i = 0;
    i < lines.length &&
    secretFindings.length < MAX_FINDINGS_PER_FILE &&
    !skipEntropyForFile(file.path);
    i++
  ) {
    if (flaggedLines.has(i)) continue;
    if (shouldSkipLine(lines[i], commentPattern)) continue;

    QUOTED_STRING_PATTERN.lastIndex = 0;
    let qMatch: RegExpExecArray | null;
    while (
      (qMatch = QUOTED_STRING_PATTERN.exec(lines[i])) !== null &&
      secretFindings.length < MAX_FINDINGS_PER_FILE
    ) {
      const value = qMatch[1];
      if (isNonSecretValue(value)) continue;
      if (isPlaceholder(value)) continue;
      if (isSequentialRun(value)) continue; // ABC…XYZ / 012345… — high entropy, not a secret
      if (value.length < MIN_ENTROPY_LENGTH) continue;

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
