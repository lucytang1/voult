// Build guard: MV3 manifest-declared content scripts load as classic scripts,
// not modules. Any static `import` in dist/content.js makes Chrome reject the
// whole bundle ("Cannot use import statement outside a module") and the error
// surfaces on chrome://extensions with no useful message. Content code must
// therefore never take a *runtime* import from a module shared with other
// entries (type-only imports are erased and fine). Fail the build loudly.
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dist = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const bundle = readFileSync(resolve(dist, "content.js"), "utf8");
if (/(^|[;{}])\s*import[\s{(]/.test(bundle) || bundle.includes("from\"./assets/") || bundle.includes("from'./assets/")) {
  console.error("FAIL: dist/content.js contains a static import — content scripts must be a single import-free IIFE.");
  process.exit(1);
}
console.log("OK: dist/content.js is import-free.");
