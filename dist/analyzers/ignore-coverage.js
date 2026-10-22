import { createIgnore } from "../ignore-match.js";
/**
 * AI-ignore checks — see docs/ignore-coverage-audit.md.
 *
 * CRITICAL framing: an ignore file is a *request, not a wall*. The tool may not
 * honour it and an agent's Read/Bash calls bypass it entirely. So:
 *   - A detected secret in the working tree is reachable by the AI whether or not
 *     an ignore pattern "covers" it. Coverage is NOT a dividing line — it's a weak
 *     secondary note at most.
 *   - Nothing here emits a positive verdict, and no output string uses confidence
 *     words (safe / protected / secure / complete) — enforced by a test.
 *   - A clean scan is bounded by scanner recall; consumers MUST surface
 *     DETECTION_DISCLAIMER so "0 findings" never reads as "no secrets present".
 *   - The caveat is shown ONCE per report by the consumer (IGNORE_CAVEAT), not
 *     repeated on every finding (repetition breeds caveat-blindness).
 */
/** Shown ONCE per report by the consumer — not repeated per finding. */
export const IGNORE_CAVEAT = "Ignore files do not stop the AI from reading these — they are best-effort and an " +
    "agent's file reads bypass them. The real fix is to remove secrets from the working " +
    "tree (env injection / secret manager) and rotate anything exposed. Verify with a " +
    "canary: write a fake secret to an ignored path and ask the agent to read it.";
/** Consumers MUST surface this on a clean scan — recall is bounded. */
export const DETECTION_DISCLAIMER = "No secrets were detected by pattern/entropy scanning. This does NOT mean none are " +
    "present — low-entropy, split, or encoded secrets evade detection.";
const AI_IGNORE_FILE = /(^|\/)\.(cursorignore|claudeignore|codeiumignore|aiexclude)$/i;
const SECRET_INTENT = /env|secret|credential|token|password|passwd|pem|key|rsa|npmrc|netrc|pfx|keystore|p12/i;
// Canonical secret shapes for the HYGIENE lint. Necessarily incomplete — real
// secrets live in infinite forms (terraform.tfvars, .aws/credentials, kubeconfig,
// .pgpass, serviceAccount.json, application.properties, …). The lint never asserts
// completeness.
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
 * PRIMARY (detected exposure): EVERY file with a detected secret sits in the
 * working tree and is reachable by the AI — ignore coverage does not change that.
 * One consolidated finding. Coverage appears only as a weak secondary note, never
 * as a divider between "exposed" and "safe".
 */
export function auditDetectedExposure(secretFilePaths, aiIgnoreFiles) {
    const files = [...new Set(secretFilePaths)].filter(Boolean);
    if (files.length === 0)
        return [];
    const matchers = aiIgnoreFiles
        .filter((f) => isAiIgnoreFile(f.path) && f.content)
        .map((f) => createIgnore(f.content.split("\n")));
    const coveredCount = files.filter((f) => matchers.some((m) => m.matchPath(f))).length;
    const list = files.slice(0, 10).join(", ") + (files.length > 10 ? ", …" : "");
    const note = coveredCount
        ? ` (${coveredCount} match an AI-ignore pattern — best-effort only, not a barrier)`
        : "";
    return [
        {
            id: `secret-ai-reachable-${files.length}`,
            filePath: files[0],
            issue: "secret-ai-reachable",
            severity: "warning",
            description: `${files.length} file(s) with a detected secret are in the working tree and reachable by the AI${note}: ${list}`,
            suggestion: "Remove these from the working tree (env injection / secret manager) and rotate.",
        },
    ];
}
/**
 * SECONDARY (hygiene lint): canonical-shape coverage gaps in one AI-ignore file.
 * Only runs when the file shows secret-protection intent. Never asserts
 * completeness; the per-finding suggestion carries only the fix line — the full
 * caveat is shown once per report.
 */
export function auditIgnoreCoverage(path, content) {
    if (!isAiIgnoreFile(path) || !content)
        return [];
    const ignore = createIgnore(content.split("\n"));
    if (ignore.patternCount === 0)
        return [];
    if (!ignore.patterns.some((p) => SECRET_INTENT.test(p)))
        return [];
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
            suggestion: `Add to ${name}: ${gaps.map((g) => `\`${g.suggest}\``).join(", ")}.`,
        },
    ];
}
//# sourceMappingURL=ignore-coverage.js.map