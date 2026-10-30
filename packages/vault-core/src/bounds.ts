// Protocol bounds — the client half of the wire contract enforced by
// `apps/server/src/endpoints/validate.rs`.
//
// Why a shared module: the server rejects any shape the v2 hierarchy cannot
// produce, and the client must reject the same shapes *before* it derives keys
// or pushes a document. The import path is the important one — its inputs come
// from a cloud file, so an unchecked `iterations` of 2^31-1 freezes PBKDF2 with
// no cancel button.
//
// The numbers are duplicated across languages because the server is Rust and
// the clients are TypeScript; each language has exactly one copy. Both copies
// are pinned by tests and documented in `docs/request-bounds.md`. Change them
// together, and only when the KDF-profile item says so.

/** Exact byte lengths produced by the v2 hierarchy in `crypto.ts`. */
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const VERIFIER_BYTES = 32;
/** 32-byte wrapped key + 16-byte GCM tag. */
export const KEY_WRAP_BYTES = 48;
export const PROOF_BYTES = 32;

/** Ciphertext sanity floor: GCM tag + at least one payload byte. */
export const MIN_VAULT_CIPHERTEXT_BYTES = 17;

/**
 * Maximum encrypted vault document. Above this the client refuses to push and
 * the server refuses to store (see D5 in `plans/p0-request-bounds.md`).
 */
export const MAX_VAULT_CIPHERTEXT_BYTES = 4 * 1024 * 1024;

/**
 * Absolute floor for *deriving* from a row that already exists.
 *
 * Deliberately separate from `KDF_ITERATIONS_WRITE_FLOOR`: when the KDF-profile
 * item raises the write floor, vaults created under the old profile must still
 * open. This one only moves when the oldest supported profile does.
 */
export const KDF_READ_FLOOR = 60_000;

/** Floor for a *new* credential (register / rewrap / password change). */
export const KDF_ITERATIONS_WRITE_FLOOR = 60_000;

/**
 * Ceiling for any iteration count the client will accept, whether read from the
 * server or carried by a backup package. It exists to bound unlock cost on the
 * slowest supported device, not as a security parameter.
 */
export const KDF_ITERATIONS_CEILING = 2_000_000;

/** The only crypto version these clients produce or understand. */
export const SUPPORTED_CRYPTO_VERSION = 2;

/** Provider file ids / revisions (cloud endpoints). */
export const MAX_REMOTE_ID_LENGTH = 512;

/** Explicit server JSON body cap; mirrored for documentation and tests. */
export const MAX_JSON_BODY_BYTES = 12 * 1024 * 1024;

/** A package carries the ciphertext as base64 plus the envelopes. */
export const MAX_PACKAGE_BYTES = 6 * 1024 * 1024;

const B64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const B64_LOOKUP: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < B64_ALPHABET.length; i += 1) {
    table[B64_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/**
 * `iterations` / salt out of range. A distinct class so callers can tell "this
 * vault's params are not something we can derive from" apart from "wrong
 * password" (which is a GCM authentication failure, not this).
 */
export class KdfParamsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KdfParamsError";
  }
}

/**
 * Validates the parameters before PBKDF2 runs.
 *
 * Called from `deriveRootKey`, the single choke point every password-bearing
 * path goes through (`createAuthKey`, `derivePasswordWrappingKey`), so a hostile
 * package or a corrupt row fails in microseconds instead of spinning.
 */
export function assertKdfParams(saltBytes: number, iterations: number): void {
  if (saltBytes !== SALT_BYTES) {
    throw new KdfParamsError(
      `Unsupported KDF salt length: ${saltBytes} bytes (expected ${SALT_BYTES}).`,
    );
  }
  if (
    !Number.isInteger(iterations) ||
    iterations < KDF_READ_FLOOR ||
    iterations > KDF_ITERATIONS_CEILING
  ) {
    throw new KdfParamsError(
      `Unsupported KDF iteration count: ${iterations} (expected ${KDF_READ_FLOOR}-${KDF_ITERATIONS_CEILING}).`,
    );
  }
}

/** Throws when an encrypted document exceeds the sync ceiling. */
export function assertVaultCiphertextSize(byteLength: number): void {
  if (byteLength > MAX_VAULT_CIPHERTEXT_BYTES) {
    throw new Error(
      `Vault ciphertext is ${byteLength} bytes; the limit is ${MAX_VAULT_CIPHERTEXT_BYTES}.`,
    );
  }
}

/**
 * Canonical standard base64, matching the server's `decode_allow_trailing_bits
 * = false` + `RequireCanonicalPadding` rules: padded to a multiple of 4,
 * padding only at the end, zero trailing bits in the final quantum.
 *
 * Hand-rolled rather than `btoa(atob(s)) === s`: the largest field is 4 MiB, and
 * spreading that into `String.fromCharCode` overflows the stack.
 */
function isCanonicalBase64(value: string): boolean {
  const len = value.length;
  if (len % 4 !== 0) return false;

  const pad = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const dataLen = len - pad;

  for (let i = 0; i < dataLen; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 128 || B64_LOOKUP[code] < 0) return false;
  }
  // `=` may only appear where the padding already is.
  for (let i = dataLen; i < len; i += 1) {
    if (value.charCodeAt(i) !== 61 /* '=' */) return false;
  }

  if (pad === 2) return (B64_LOOKUP[value.charCodeAt(dataLen - 1)] & 0x0f) === 0;
  if (pad === 1) return (B64_LOOKUP[value.charCodeAt(dataLen - 1)] & 0x03) === 0;
  return true;
}

/** Decoded byte length, or `null` when the value is not canonical base64. */
export function decodedBase64Length(value: string): number | null {
  const s = value.trim();
  if (!isCanonicalBase64(s)) return null;
  const pad = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
  return (s.length / 4) * 3 - pad;
}

function decodeCanonical(s: string): Uint8Array {
  const binary = atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Decodes canonical base64 that must be exactly `expectedBytes` long. */
export function parseBase64Exact(
  value: string,
  expectedBytes: number,
): Uint8Array | null {
  if (decodedBase64Length(value) !== expectedBytes) return null;
  return decodeCanonical(value.trim());
}

/** Decodes canonical base64 whose length must fall in `[minBytes, maxBytes]`. */
export function parseBase64Bounded(
  value: string,
  minBytes: number,
  maxBytes: number,
): Uint8Array | null {
  const len = decodedBase64Length(value);
  if (len === null || len < minBytes || len > maxBytes) return null;
  return decodeCanonical(value.trim());
}
