/**
 * A minimal, zero-dependency gitignore matcher implementing a documented subset
 * of gitignore semantics — shared across analyzers (e.g. the AI-ignore coverage
 * audit). Pure: no filesystem access.
 *   - `#` comments and blank lines are skipped
 *   - `!pattern` negates (un-ignores); last matching rule wins
 *   - a trailing `/` makes the pattern directory-only (matches its contents)
 *   - a leading `/` anchors to the root; a pattern containing a `/` is anchored
 *   - a pattern with no `/` matches that name at any depth
 *   - `*` matches within a segment, `**` across segments, `?` one char
 */
export interface Ignore {
    matchPath(relPath: string): boolean;
    readonly patternCount: number;
    /** Raw (non-comment, non-blank) pattern bodies, `!`-stripped — for inspection. */
    readonly patterns: string[];
}
export declare function createIgnore(lines: string[]): Ignore;
//# sourceMappingURL=ignore-match.d.ts.map