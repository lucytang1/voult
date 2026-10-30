# @voult/vault-core

Shared pure-TS vault logic for the Expo web app (`apps/client`) and the MV3
extension (`apps/extension`). No React, no Expo, no `react-native` — WebCrypto
only. Single source of truth for:

- `crypto.ts` — v2 KDF hierarchy (PBKDF2→HKDF `auth`/`vault-wrap-v2`), AES-GCM
  encrypt/decrypt, key wrap/unwrap, verifiers. Same key bytes, same labels as
  the web app has always used — no migration involved.
- `schema.ts` — `VaultItem` (+ optional `origin`/`urls` for origin-bound
  matching), sync op schemas, server API shapes.
- `merge.ts` — deterministic intent-replay policy (idempotent create, per-field
  LWW update, sticky delete, quarantine). No secret logging.
- `origin.ts` — origin canonicalization + ranked matching (exact → linked →
  weaker subdomain).

## Commands

```sh
npm install        # once per checkout — node_modules/ is gitignored
npm run build      # emits dist/ (consumed by client + extension)
npm test           # builds test bundle + runs node --test (19 tests)
npm run typecheck
```

## Rebuild contract

Consumers import the compiled `dist/` (package `main`). Both consumer builds
rebuild core first (`apps/client: build:web`, `apps/extension: build`), so
release builds can never go stale. **Expo dev (`npm run web`) does not
rebuild core** — after editing `packages/vault-core`, run
`npm --prefix ../../packages/vault-core run build` (from `apps/client`) or
restart the flow before testing.

Consumer builds go through `scripts/build-vault-core.sh`, which installs this
package's dependencies (`npm ci` from the committed lockfile) when
`node_modules/` is missing and then builds `dist/`. That step is required
because `file:` dependencies are only symlinked by npm — a fresh clone and CI
never get `packages/vault-core/node_modules`, and `tsc` resolves `zod` from
here, not from `apps/client/node_modules`.
