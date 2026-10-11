# Publishing `@deepwissen/*` to npm

Two packages, published in this order (vet depends on preflight-core):

1. `@deepwissen/preflight-core` — the engine
2. `@deepwissen/vet` — the CLI

Both are **scoped and public**; `publishConfig.access = public` is set so a plain
`npm publish` works (no `--access public` needed). `prepublishOnly` rebuilds
`dist/` automatically on publish.

## One-time prerequisites

Publish as the **`deepwissen`** npm account — the `@deepwissen` scope maps to it
(a scope can be an npm user or an org).

```bash
npm login                      # authenticate as `deepwissen`
npm whoami                     # -> deepwissen
```

(If `@deepwissen` is an npm *org* rather than a user account, just ensure the
account you log in with is a member with publish rights.)

## Step 1 — publish preflight-core

```bash
cd preflight-core
npm run lint && npm run typecheck && npm run test:coverage && npm run build
npm publish --dry-run          # preview the tarball contents (no upload)
npm publish                    # publishes @deepwissen/preflight-core@0.1.0
```

Verify: <https://www.npmjs.com/package/@deepwissen/preflight-core>

## Step 2 — point vet at the published engine, then publish

The repo currently depends on the engine via a git URL. Switch it to the npm
version now that the engine is live:

```bash
cd ../vet
npm pkg set dependencies.@deepwissen/preflight-core=^0.1.0
npm install                    # updates package-lock.json to the npm dep
npm run lint && npm run typecheck && npm run test:coverage && npm run build
git add package.json package-lock.json
git commit -m "chore: depend on @deepwissen/preflight-core from npm"
git push origin main

npm publish --dry-run          # preview
npm publish                    # publishes @deepwissen/vet@0.1.0
```

Verify end-to-end:

```bash
npx @deepwissen/vet --version  # -> 0.1.0
```

## Hands-off releases — npm Trusted Publishing (OIDC)

After the first manual publish above has created each package, switch to
tokenless, automated releases via `.github/workflows/publish.yml` (OIDC). There
is **no `NPM_TOKEN` stored anywhere** — GitHub authenticates to npm per-run with
a short-lived OIDC credential, and npm attaches build provenance automatically.

**One-time setup on npmjs.com (per package):**

1. Open the package → **Settings** → **Trusted Publisher**.
2. Add a GitHub Actions publisher:
   - Organization / repository: `deepwissen/preflight-core` (and `deepwissen/vet`)
   - Workflow filename: `publish.yml`
   - Environment: leave blank (or set one if you add a protected GH environment).

**Each release after that — no token, no manual publish:**

```bash
npm version patch        # or minor | major — bumps package.json and commits a tag
git push --follow-tags   # pushes the commit AND the vX.Y.Z tag
```

Pushing the `vX.Y.Z` tag triggers `publish.yml`, which lint/typecheck/tests/
builds, verifies the tag matches `package.json`, and runs `npm publish` over
OIDC. Watch it under the repo's **Actions** tab.

> Trusted Publishing needs the package to already exist, so the **first** release
> of each package is the manual `npm publish` above. Every release afterward is
> the tag-push flow.

## Notes

- **Versioning:** bump with `npm version patch|minor|major` before each future
  publish (it updates `package.json` and tags the commit). Keep `vet/src/cli.ts`
  `VERSION` in sync with `vet/package.json`.
- **Mistake recovery:** you cannot overwrite a published version. Within 72h you
  may `npm unpublish <pkg>@<version>`; otherwise `npm deprecate` and publish a
  fixed patch.
- **What ships:** `files: ["dist"]` plus `README.md`, `LICENSE`, and
  `package.json` (always included). Confirm with `npm publish --dry-run`.
