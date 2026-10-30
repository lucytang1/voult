// Password KDF profiles — Argon2id only.
//
// The password root is Argon2id (RFC 9106). WebCrypto has no Argon2 and no
// scrypt, so the implementation is @noble/hashes: pure JS, zero dependencies,
// pinned exactly. A WASM build would be faster but requires
// `'wasm-unsafe-eval'` in the MV3 `extension_pages` CSP and asset plumbing in
// two bundlers; that trade was rejected in plans/p0-kdf-profile.md.
//
// This module imports nothing from `crypto.ts`. `crypto.ts` delegates
// password-root derivation here, so the reverse edge would be a cycle; base64
// helpers therefore live in `bytes.ts`.
//
// A profile is a *closed, append-only* set of parameter tuples. The descriptor
// is self-describing (so a backup written today is readable by a future
// client), but a tuple that is not on the ladder is rejected rather than
// interpreted. Adding a rung must never change how an existing row derives.
//
// There is deliberately no legacy algorithm and no free-form parameter range:
// there are no released vaults, so nothing needs PBKDF2 kept alive.

import { argon2id } from "@noble/hashes/argon2.js";

import { b64, fromB64 } from "./bytes.js";

export type KdfParams = {
  /** Algorithm identifier. Only Argon2id v1.3 (BLAKE2b) is accepted. */
  readonly algorithm: "argon2id";
  /** Memory cost in KiB. Exactly a ladder rung; never free-form. */
  readonly memory_kib: number;
  /** Number of passes (Argon2 `t`). */
  readonly time_cost: number;
  /** Lanes (Argon2 `p`). Always 1 here: lanes give an attacker parallelism too. */
  readonly parallelism: number;
};

/** Bump when the ladder changes shape (not when a rung is appended). */
export const KDF_LADDER_VERSION = 1;

/** Salt length expected by every profile, in bytes (128 bits, per RFC 9106). */
export const KDF_SALT_BYTES = 16;

/** Derivation output length: one 256-bit password root. */
const KDF_DK_LEN = 32;

/**
 * The ladder, cheapest first. Costs are monotonic by construction, which lets
 * calibration stop at the first rung that misses the budget.
 *
 * - 19 MiB / t=2 is the OWASP minimum and the hard floor.
 * - 32 MiB / t=3 is the default when calibration has not run.
 * - 64 MiB / t=3 is RFC 9106's low-memory shape with p reduced from 4 to 1.
 */
const ARGON2_RUNGS: readonly KdfParams[] = [
  Object.freeze({
    algorithm: "argon2id",
    memory_kib: 19_456,
    time_cost: 2,
    parallelism: 1,
  }),
  Object.freeze({
    algorithm: "argon2id",
    memory_kib: 32_768,
    time_cost: 3,
    parallelism: 1,
  }),
  Object.freeze({
    algorithm: "argon2id",
    memory_kib: 65_536,
    time_cost: 3,
    parallelism: 1,
  }),
];

/** Append-only registry. Never remove a rung: existing vaults derive with it. */
export const KDF_LADDER: readonly KdfParams[] = Object.freeze(ARGON2_RUNGS);

/** The minimum acceptable profile. Never go below this, even on slow devices. */
export const KDF_FLOOR: KdfParams = KDF_LADDER[0];

/** Used only when calibration has not run yet (e.g. a cached target is missing). */
export const DEFAULT_KDF: KdfParams = KDF_LADDER[1];

/** Default wall-clock budget for one derivation on the creating device. */
export const DEFAULT_KDF_BUDGET_MS = 700;

/** Thrown when a descriptor is not one of the published rungs. */
export class UnknownKdfProfileError extends Error {
  readonly code = "UNKNOWN_KDF_PROFILE";

  constructor(value: unknown) {
    let rendered: string;
    try {
      rendered = JSON.stringify(value);
    } catch {
      rendered = String(value);
    }
    super(`Unknown KDF profile: ${rendered ?? String(value)}`);
    this.name = "UnknownKdfProfileError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Structural check only. Use `isKnownKdf` before deriving: a well-formed
 * descriptor that is not on the ladder is still rejected.
 */
export function isKdfParams(value: unknown): value is KdfParams {
  if (!isRecord(value)) return false;
  const { algorithm, memory_kib, time_cost, parallelism } = value;
  return (
    algorithm === "argon2id" &&
    typeof memory_kib === "number" &&
    Number.isInteger(memory_kib) &&
    memory_kib > 0 &&
    typeof time_cost === "number" &&
    Number.isInteger(time_cost) &&
    time_cost > 0 &&
    typeof parallelism === "number" &&
    Number.isInteger(parallelism) &&
    parallelism > 0
  );
}

function sameKdf(a: KdfParams, b: KdfParams): boolean {
  return (
    a.algorithm === b.algorithm &&
    a.memory_kib === b.memory_kib &&
    a.time_cost === b.time_cost &&
    a.parallelism === b.parallelism
  );
}

/** True only for the exact published tuples. */
export function isKnownKdf(value: unknown): value is KdfParams {
  return isKdfParams(value) && KDF_LADDER.some((rung) => sameKdf(rung, value));
}

/** Structural equality for two descriptors, used by stale-metadata checks. */
export function kdfEquals(a: unknown, b: unknown): boolean {
  return isKdfParams(a) && isKdfParams(b) && sameKdf(a, b);
}

/**
 * 1-based position on the ladder, or 0 for anything unknown.
 *
 * Used by the no-downgrade rule (server and client): a credential may move to
 * an equal or higher rank, never lower. Rank is a policy order over published
 * profiles, not a measured comparison between parameter sets.
 */
export function kdfRank(value: unknown): number {
  if (!isKdfParams(value)) return 0;
  const index = KDF_LADDER.findIndex((rung) => sameKdf(rung, value));
  return index < 0 ? 0 : index + 1;
}

/** Human-readable label for UI and logs. Contains no secret material. */
export function describeKdf(value: unknown): string {
  if (!isKdfParams(value)) return "Unknown protection";
  const memoryMb = Math.round(value.memory_kib / 1024);
  return `Argon2id · ${memoryMb} MB · ${value.time_cost} pass${value.time_cost === 1 ? "" : "es"}`;
}

/**
 * Derives the 256-bit password root.
 *
 * `await` is intentional even though the Argon2 call is synchronous today: it
 * lets a future move into a Web Worker (or a WASM implementation) change no
 * call site. Until then the caller must assume the main thread blocks for the
 * duration; the calibration ladder bounds that to the device budget.
 *
 * Rejects an off-ladder descriptor *before* allocating any memory, so a server
 * that serves `memory_kib: 2^31` cannot make the client allocate gigabytes.
 */
export async function derivePasswordRoot(
  password: string,
  saltB64: string,
  kdf: KdfParams,
): Promise<Uint8Array> {
  if (!isKnownKdf(kdf)) {
    throw new UnknownKdfProfileError(kdf);
  }

  const salt = fromB64(saltB64);
  if (salt.length !== KDF_SALT_BYTES) {
    throw new Error(
      `KDF salt must be ${KDF_SALT_BYTES} bytes, got ${salt.length}.`,
    );
  }

  // UTF-8 bytes exactly as the old PBKDF2 path encoded the password. No
  // normalization is applied: changing it would change what an existing
  // password means.
  return argon2id(new TextEncoder().encode(password), salt, {
    m: kdf.memory_kib,
    t: kdf.time_cost,
    p: kdf.parallelism,
    dkLen: KDF_DK_LEN,
  });
}

// A fixed, non-secret salt for timing probes. The derived bytes are discarded;
// this must never be used to derive a real credential.
const CALIBRATION_SALT_B64 = b64(new Uint8Array(KDF_SALT_BYTES));
const CALIBRATION_PASSWORD = "voult-kdf-calibration-v1";

function currentTime(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

/**
 * Picks the highest ladder rung that derives within `budgetMs` on this device.
 *
 * Runs one probe per rung (the ladder is monotonic, so it stops at the first
 * miss), after a tiny warm-up so the first measurement is not paying for JIT.
 * The floor is returned even when it misses the budget: security beats latency,
 * and the UI can show a longer "Unlocking…" state.
 *
 * Results are device-local and should be cached by the caller; this function
 * does no caching itself and never sees the user's password.
 */
export async function calibrateKdf(
  options: { budgetMs?: number; now?: () => number } = {},
): Promise<{ kdf: KdfParams; measuredMs: number }> {
  const budgetMs = options.budgetMs ?? DEFAULT_KDF_BUDGET_MS;
  const now = options.now ?? currentTime;

  // Warm the JS path. Deliberately tiny and not on the ladder.
  argon2id(new TextEncoder().encode(CALIBRATION_PASSWORD), new Uint8Array(KDF_SALT_BYTES), {
    m: 1024,
    t: 1,
    p: 1,
    dkLen: KDF_DK_LEN,
  });

  let chosen = KDF_FLOOR;
  let measuredMs = Number.POSITIVE_INFINITY;

  for (const rung of KDF_LADDER) {
    const started = now();
    const root = await derivePasswordRoot(
      CALIBRATION_PASSWORD,
      CALIBRATION_SALT_B64,
      rung,
    );
    const elapsedMs = now() - started;
    // Best-effort: the probe result is not a key and is never used.
    root.fill(0);

    if (elapsedMs > budgetMs) {
      // Monotonic ladder: every later rung is slower. If the floor itself
      // missed, it is still the answer (never go below the OWASP minimum).
      if (rung === KDF_FLOOR) {
        chosen = rung;
        measuredMs = elapsedMs;
      }
      break;
    }

    chosen = rung;
    measuredMs = elapsedMs;
  }

  return { kdf: chosen, measuredMs };
}
