function globToRegex(glob) {
    let re = "";
    for (let i = 0; i < glob.length; i++) {
        const c = glob[i];
        if (c === "*") {
            if (glob[i + 1] === "*") {
                i++;
                if (glob[i + 1] === "/") {
                    i++;
                    re += "(?:.*/)?";
                }
                else {
                    re += ".*";
                }
            }
            else {
                re += "[^/]*";
            }
        }
        else if (c === "?") {
            re += "[^/]";
        }
        else if (/[.+^${}()|[\]\\]/.test(c)) {
            re += "\\" + c;
        }
        else {
            re += c;
        }
    }
    return re;
}
function compile(body) {
    const dirOnly = /\/$/.test(body);
    let pattern = body.replace(/\/+$/, "");
    const anchored = pattern.startsWith("/") || pattern.includes("/");
    if (pattern.startsWith("/"))
        pattern = pattern.slice(1);
    const core = globToRegex(pattern);
    const head = anchored ? "^" : "^(?:.*/)?";
    const tail = dirOnly ? "/.*$" : "(?:/.*)?$";
    return new RegExp(head + core + tail);
}
export function createIgnore(lines) {
    const rules = [];
    const patterns = [];
    for (const raw of lines) {
        const line = raw.replace(/\r$/, "").trim();
        if (!line || line.startsWith("#"))
            continue;
        const negated = line.startsWith("!");
        const body = negated ? line.slice(1) : line;
        if (!body)
            continue;
        rules.push({ negated, re: compile(body) });
        patterns.push(body);
    }
    return {
        patternCount: rules.length,
        patterns,
        matchPath(relPath) {
            const rel = relPath.replace(/\\/g, "/").replace(/^\.\//, "");
            let ignored = false;
            for (const r of rules) {
                if (r.re.test(rel))
                    ignored = !r.negated;
            }
            return ignored;
        },
    };
}
//# sourceMappingURL=ignore-match.js.map