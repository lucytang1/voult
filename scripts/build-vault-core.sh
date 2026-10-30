#!/usr/bin/env bash
set -euo pipefail

# Build @voult/vault-core (packages/vault-core) before any consumer build.
#
# Why this exists: vault-core is a standalone npm package with its own
# package.json + lockfile. apps/client and apps/extension consume it through
# `"file:../../packages/vault-core"`, and npm only *symlinks* a file:
# dependency — it does NOT install that package's own dependencies. Those
# (zod, typescript) live in packages/vault-core/node_modules, which is
# gitignored, so a fresh clone and every CI runner start without them.
#
# TypeScript resolves imports relative to the file doing the importing, so it
# walks packages/vault-core/node_modules → packages/node_modules →
# <repo>/node_modules. It never looks in apps/client/node_modules, even though
# zod is installed there. That is why the release job died in the client build:
#
#   > @voult/vault-core@0.1.0 build
#   > tsc -p tsconfig.build.json
#   src/schema.ts(11,20): error TS2307: Cannot find module 'zod' ...
#
# Installing here (once, from the committed lockfile) makes the build
# reproducible from any checkout, whether it is CI, a fresh clone, or a
# worktree that has never seen an `npm install` in packages/vault-core.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$ROOT/packages/vault-core"

if [[ ! -f "$CORE/package.json" ]]; then
  echo "ERROR: $CORE/package.json not found" >&2
  exit 1
fi

# Install only when the toolchain is missing. A populated node_modules is
# reused so local iteration stays fast; a clean checkout or CI runner always
# gets a deterministic `npm ci` from packages/vault-core/package-lock.json.
# `zod` is checked by name because it is the import that used to fail.
if [[ ! -x "$CORE/node_modules/.bin/tsc" || ! -d "$CORE/node_modules/zod" ]]; then
  echo "--- Installing vault-core dependencies (npm ci) ---"
  ( cd "$CORE" && npm ci --no-audit --no-fund )
fi

echo "--- Building vault-core (dist/) ---"
( cd "$CORE" && npm run build )

# Both consumers import the compiled entry point declared in package.json
# ("main": "./dist/index.js"). Fail loudly here instead of letting Expo/Metro
# report a confusing module-resolution error later.
if [[ ! -f "$CORE/dist/index.js" || ! -f "$CORE/dist/index.d.ts" ]]; then
  echo "ERROR: vault-core build produced no dist/index.js or dist/index.d.ts" >&2
  exit 1
fi
