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

interface Rule {
  negated: boolean;
  re: RegExp;
}

function globToRegex(glob: string): string {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") {
          i++;
          re += "(?:.*/)?";
        } else {
          re += ".*";
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if (/[.+^${}()|[\]\\]/.test(c)) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return re;
}

function compile(body: string): RegExp {
  const dirOnly = /\/$/.test(body);
  let pattern = body.replace(/\/+$/, "");
  const anchored = pattern.startsWith("/") || pattern.includes("/");
  if (pattern.startsWith("/")) pattern = pattern.slice(1);

  const core = globToRegex(pattern);
  const head = anchored ? "^" : "^(?:.*/)?";
  const tail = dirOnly ? "/.*$" : "(?:/.*)?$";
  return new RegExp(head + core + tail);
}

export function createIgnore(lines: string[]): Ignore {
  const rules: Rule[] = [];
  const patterns: string[] = [];
  for (const raw of lines) {
    const line = raw.replace(/\r$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    const negated = line.startsWith("!");
    const body = negated ? line.slice(1) : line;
    if (!body) continue;
    rules.push({ negated, re: compile(body) });
    patterns.push(body);
  }

  return {
    patternCount: rules.length,
    patterns,
    matchPath(relPath: string): boolean {
      const rel = relPath.replace(/\\/g, "/").replace(/^\.\//, "");
      let ignored = false;
      for (const r of rules) {
        if (r.re.test(rel)) ignored = !r.negated;
      }
      return ignored;
    },
  };
}
