This project uses `patch-package` for `@sqlite.org/sqlite-wasm`.

Notes:
- Keep `@sqlite.org/sqlite-wasm` pinned to an exact version in `package.json`.
- When upgrading sqlite-wasm:
  1. Update the version in `package.json`.
  2. Run `npm install`.
  3. Re-apply equivalent edits in `node_modules/@sqlite.org/sqlite-wasm/dist/index.mjs`.
  4. Re-generate patch: `npx patch-package @sqlite.org/sqlite-wasm`.
  5. Re-sync static web assets: `npm run sync:sqlite-web`.
