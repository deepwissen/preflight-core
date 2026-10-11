# Publishing `@deepwissen/*` to npm

Two packages, published in this order (vet depends on preflight-core):

1. `@deepwissen/preflight-core` — the engine
2. `@deepwissen/vet` — the CLI

Both are **scoped and public**; `publishConfig.access = public` is set so a plain
`npm publish` works (no `--access public` needed). `prepublishOnly` rebuilds
`dist/` automatically on publish.

## One-time prerequisites

```bash
npm login                      # authenticate
npm whoami                     # confirm you're logged in
# Ensure the "deepwissen" org exists on npmjs.com and your user is a member
# (create it at https://www.npmjs.com/org/create if needed).
```

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

## Notes

- **Versioning:** bump with `npm version patch|minor|major` before each future
  publish (it updates `package.json` and tags the commit). Keep `vet/src/cli.ts`
  `VERSION` in sync with `vet/package.json`.
- **Mistake recovery:** you cannot overwrite a published version. Within 72h you
  may `npm unpublish <pkg>@<version>`; otherwise `npm deprecate` and publish a
  fixed patch.
- **What ships:** `files: ["dist"]` plus `README.md`, `LICENSE`, and
  `package.json` (always included). Confirm with `npm publish --dry-run`.
