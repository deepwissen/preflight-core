import { createIgnore } from "../ignore-match.js";
/**
 * AI-ignore checks. Two detectors, in priority order:
 *
 *   1. `auditSecretExposure` (GROUND TRUTH, primary) — a file where a scanner
 *      actually found a secret that no AI-ignore pattern covers. Real risk in
 *      *this* repo, not a proxy.
 *   2. `auditIgnoreCoverage` (HYGIENE LINT, secondary) — pattern gaps against a
 *      small canonical set (e.g. a `.env.*` glob that misses a bare `.env`).
 *
 * CRITICAL framing — read before changing anything here:
 * An ignore file is a *request*, not a wall. The tool may not honour it, and an
 * agent's Read/Bash calls bypass indexing exclusions entirely. So neither detector
 * may ever imply "the AI can't read this." They emit ONLY gaps/exposures, never a
 * "complete"/"protected" verdict, and every finding carries CAVEAT. A clean run
 * means "no pattern gaps found" — NOT "your secrets are safe from the AI."
 */
/** The permanent caveat on every finding — the tool must not grant false confidence. */
const CAVEAT = "This is pattern hygiene, not protection: an AI-ignore file is best-effort and an " +
    "agent's file reads bypass it — the real fix is to keep secrets OUT of the working " +
    "tree (env injection / secret manager) and rotate anything already exposed. Verify " +
    "with a canary: drop a fake secret in an ignored path and ask the agent to read it.";
/** AI-tool ignore files whose job is to keep content away from the model. */
const AI_IGNORE_FILE = /(^|\/)\.(cursorignore|claudeignore|codeiumignore|aiexclude)$/i;
/** A file shows secret-protection *intent* if any pattern mentions a secret-ish term. */
const SECRET_INTENT = /env|secret|credential|token|password|passwd|pem|key|rsa|npmrc|netrc|pfx|keystore|p12/i;
// Canonical secret shapes for the HYGIENE lint. Necessarily incomplete — real
// secrets live in infinite forms (terraform.tfvars, .aws/credentials, kubeconfig,
// .pgpass, serviceAccount.json, application.properties, …). This is why the lint
// is secondary and never asserts completeness.
const PROBES = [
    { path: ".env", label: "a bare .env", suggest: "**/.env" },
    { path: "prod.env", label: "*.env files", suggest: "**/*.env" },
    { path: "id_rsa", label: "SSH private keys (id_rsa)", suggest: "**/id_rsa*" },
    { path: "private.pem", label: "PEM private keys", suggest: "**/*.pem" },
    { path: "server.key", label: "key files", suggest: "**/*.key" },
    { path: "credentials.json", label: "credential files", suggest: "**/*credential*" },
    { path: ".npmrc", label: ".npmrc (may hold a token)", suggest: "**/.npmrc" },
];
export function isAiIgnoreFile(path) {
    return AI_IGNORE_FILE.test(path);
}
/**
 * PRIMARY (ground truth): files where a scanner actually found a secret that no
 * AI-ignore pattern covers. Fires loudest on the careless case — a secret present
 * with no protective patterns (or no AI-ignore file at all) → everything exposed.
 * Consolidated into one finding (the remediation is the same for all: get them out).
 */
export function auditSecretExposure(secretFilePaths, aiIgnoreFiles) {
    const files = [...new Set(secretFilePaths)];
    if (files.length === 0)
        return [];
    const matchers = aiIgnoreFiles
        .filter((f) => isAiIgnoreFile(f.path) && f.content)
        .map((f) => createIgnore(f.content.split("\n")));
    const exposed = files.filter((f) => !matchers.some((m) => m.matchPath(f)));
    if (exposed.length === 0)
        return [];
    const list = exposed.slice(0, 10).join(", ") + (exposed.length > 10 ? ", …" : "");
    return [
        {
            id: `secret-ai-reachable-${exposed.length}`,
            filePath: exposed[0],
            issue: "secret-ai-reachable",
            severity: "warning",
            description: `${exposed.length} file(s) with a detected secret are not covered by any AI-ignore and are reachable by the AI: ${list}`,
            suggestion: CAVEAT,
        },
    ];
}
/**
 * SECONDARY (hygiene lint): canonical-shape coverage gaps in one AI-ignore file.
 * Only runs when the file shows secret-protection intent (it's lint for files that
 * are *trying*). Never asserts completeness — the canon is necessarily partial.
 */
export function auditIgnoreCoverage(path, content) {
    if (!isAiIgnoreFile(path) || !content)
        return [];
    const ignore = createIgnore(content.split("\n"));
    if (ignore.patternCount === 0)
        return [];
    if (!ignore.patterns.some((p) => SECRET_INTENT.test(p)))
        return []; // no intent → no lint
    const gaps = PROBES.filter((p) => !ignore.matchPath(p.path));
    if (gaps.length === 0)
        return [];
    const name = path.split("/").pop() ?? path;
    return [
        {
            id: `ignore-coverage-gap-${path}`,
            filePath: path,
            issue: "ignore-coverage-gap",
            severity: "warning",
            matchedText: gaps.map((g) => g.suggest).join(" "),
            description: `Pattern hygiene: ${name} covers some secret shapes but not others — missing ${gaps
                .map((g) => g.label)
                .join(", ")} (a common example: a \`.env.*\` glob does not match a bare \`.env\`)`,
            suggestion: `Add to ${name}: ${gaps.map((g) => `\`${g.suggest}\``).join(", ")}. ${CAVEAT}`,
        },
    ];
}
//# sourceMappingURL=ignore-coverage.js.map