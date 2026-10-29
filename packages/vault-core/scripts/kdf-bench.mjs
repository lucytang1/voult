#!/usr/bin/env node
// Reproducible per-rung timing for the password KDF ladder.
//
// This is a developer tool, not shipped code. Run it after a build:
//   npm run build && node scripts/kdf-bench.mjs
//
// Timing depends on the machine, the JS engine and background load. The point
// is to sanity-check the calibration ladder on the hardware you care about,
// not to produce a benchmark grade number.

import { KDF_LADDER, derivePasswordRoot } from "../dist/kdf.js";
import { b64 } from "../dist/bytes.js";

const PASSWORD = "correct horse battery staple";
const SALT_B64 = b64(new Uint8Array(16).map((_, i) => i));

console.log("Argon2id ladder (one run per rung, plus one warm-up pass)\n");

// Warm the implementation once so the first rung is not paying for JIT.
await derivePasswordRoot(PASSWORD, SALT_B64, KDF_LADDER[0]);

for (const rung of KDF_LADDER) {
  const runs = 3;
  const started = performance.now();
  for (let i = 0; i < runs; i += 1) {
    const root = await derivePasswordRoot(PASSWORD, SALT_B64, rung);
    root.fill(0);
  }
  const elapsed = (performance.now() - started) / runs;
  const memoryMb = Math.round(rung.memory_kib / 1024);
  console.log(
    `m=${memoryMb} MiB  t=${rung.time_cost}  p=${rung.parallelism}  →  ${elapsed.toFixed(1)} ms`,
  );
}

console.log(
  "\nCalibration budget defaults to 700 ms per derivation; the floor is always used if nothing fits.",
);
