// Shared vault crypto — pure WebCrypto, no React/Expo/react-native imports.
//
// Single source of truth for the v2 hierarchy, imported by both the Expo web
// app and the MV3 extension service worker / popup. Ported from
// apps/client/src/lib/crypto/index.web.ts with two deliberate fixes:
//  - generateSalt() no longer returns empty bytes off-web (the old
//    `Platform.OS !== "web"` early-return bricked native and would silently
//    weaken any non-DOM consumer). All consumers now require WebCrypto.
//  - uuid() prefers crypto.randomUUID, then getRandomValues, and only then a
//    (non-cryptographic, clearly marked) Math.random fallback.

import { assertKdfParams } from "./bounds.js";

const ITERATIONS = 60000;

export const CRYPTO_VERSION = 2;
export const PBKDF2_ITERATIONS = ITERATIONS;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// HKDF info labels. Authentication and vault-key wrapping use distinct labels
// so the two derived keys are cryptographically separated even though they
// share one PBKDF2 root.
const HKDF_INFO_AUTH = "auth";
const HKDF_INFO_VAULT_WRAP = "vault-wrap-v2";

function getCrypto(): Crypto {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.subtle || !cryptoApi.getRandomValues) {
    throw new Error("Web Crypto API is not available in this environment.");
  }
  return cryptoApi;
}

function generateSalt(): Uint8Array {
  const cryptoApi = getCrypto();
  const array = new Uint8Array(16);
  cryptoApi.getRandomValues(array);
  return new Uint8Array(array);
}

export function newSaltB64(): string {
  return b64(generateSalt());
}

/** Generates a stable, client-side vault UUID (embedded in the encrypted doc). */
export function uuid(): string {
  const c = globalThis.crypto as Crypto | undefined;
  if (c && "randomUUID" in c && typeof c.randomUUID === "function") {
    return c.randomUUID();
  }
  if (c?.getRandomValues) {
    // RFC 4122 v4 from CSPRNG when randomUUID is unavailable (e.g. workers).
    const bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  // Last-resort fallback for non-crypto environments (tests only). Never
  // relied upon for real vault ids — callers in production always have
  // WebCrypto (getCrypto() throws first on the key-derivation path).
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (ch) => {
    const r = (Math.random() * 16) | 0;
    const v = ch === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function fromB64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

async function deriveRootKey(
  masterPassword: string,
  saltPwdBytes: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  // Single choke point for every password-bearing path (createAuthKey,
  // derivePasswordWrappingKey, and therefore signup, login, recovery rewrap and
  // cloud import). Bounds are checked before WebCrypto does any work, so a
  // hostile package or a corrupt row fails in microseconds instead of pinning
  // the tab in PBKDF2 for minutes.
  assertKdfParams(saltPwdBytes.length, iterations);
  // Copy into a fresh ArrayBuffer-backed view: WebCrypto's BufferSource types
  // require ArrayBuffer (not SharedArrayBuffer), and Uint8Array.from() types
  // as ArrayBufferLike under TS 5.7+ generics.
  const saltBytes = Uint8Array.from(saltPwdBytes) as Uint8Array<ArrayBuffer>;
  const cryptoApi = getCrypto();
  const pwKey = await cryptoApi.subtle.importKey(
    "raw",
    encoder.encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const rootBits = await cryptoApi.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations,
    },
    pwKey,
    256,
  );
  return new Uint8Array(rootBits);
}

async function hkdfExpand(
  rawKeyByte: Uint8Array,
  info: string,
  length: number,
  salt: Uint8Array = new Uint8Array([]),
): Promise<Uint8Array> {
  const keyBytes = Uint8Array.from(rawKeyByte) as Uint8Array<ArrayBuffer>;
  const cryptoApi = getCrypto();
  const baseKey = await cryptoApi.subtle.importKey("raw", keyBytes, "HKDF", false, [
    "deriveBits",
  ]);

  const bits = await cryptoApi.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: buf(salt),
      info: encoder.encode(info),
    },
    baseKey,
    length * 8,
  );

  return new Uint8Array(bits);
}

async function makeEncKey(rawEncBytes: Uint8Array, extractable = false): Promise<CryptoKey> {
  const encBytes = Uint8Array.from(rawEncBytes) as Uint8Array<ArrayBuffer>;
  const cryptoApi = getCrypto();
  return cryptoApi.subtle.importKey(
    "raw",
    encBytes,
    { name: "AES-GCM" },
    extractable,
    ["encrypt", "decrypt"],
  );
}

async function makeAuthKey(rawAuthBytes: Uint8Array): Promise<CryptoKey> {
  const authBytes = Uint8Array.from(rawAuthBytes) as Uint8Array<ArrayBuffer>;
  const cryptoApi = getCrypto();
  return cryptoApi.subtle.importKey(
    "raw",
    authBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/**
 * Casts a view to the ArrayBuffer-backed BufferSource the WebCrypto typings
 * require (TS 5.7+ generics type most constructed views as ArrayBufferLike).
 * Safe at runtime: WebCrypto accepts any Uint8Array regardless of backing.
 */
function buf(view: Uint8Array): BufferSource {
  return view as unknown as Uint8Array<ArrayBuffer>;
}

async function signHmac(key: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const cryptoApi = getCrypto();
  const sig = await cryptoApi.subtle.sign("HMAC", key, buf(message));
  return new Uint8Array(sig); // 32 bytes for HMAC-SHA256
}

export async function computeAuthVerifier(authKey: CryptoKey): Promise<Uint8Array> {
  const msg = concatBytes(encoder.encode("auth-v1|"), encoder.encode("|static"));
  return signHmac(authKey, msg);
}

/** Returns base64 auth verifier string for API auth (vault_verifier). */
export async function getAuthVerifierB64(authKey: CryptoKey): Promise<string> {
  const verifier = await computeAuthVerifier(authKey);
  return b64(verifier);
}

export async function encrypt(
  plain: string,
  encryptionKey: CryptoKey,
): Promise<{ iv: Uint8Array; cipher: Uint8Array }> {
  const cryptoApi = getCrypto();
  // Fresh 96-bit nonce per encryption — never reused under one key.
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const cipher = await cryptoApi.subtle.encrypt(
    { name: "AES-GCM", iv: buf(iv) },
    encryptionKey,
    buf(encoder.encode(plain)),
  );
  return {
    iv,
    cipher: new Uint8Array(cipher),
  };
}

export async function decrypt(
  cipherB64: string,
  ivB64: string,
  encryptionKey: CryptoKey,
): Promise<string> {
  const cipherBytes = fromB64(cipherB64);
  const ivBytes = fromB64(ivB64);
  const cryptoApi = getCrypto();
  // AES-GCM failure (wrong key / tampered bytes) throws — callers treat any
  // rejection as auth failure, never fall back to another parse.
  const plain = await cryptoApi.subtle.decrypt(
    { name: "AES-GCM", iv: buf(ivBytes) },
    encryptionKey,
    buf(cipherBytes),
  );
  return decoder.decode(plain);
}

// --- Version-2 key hierarchy -------------------------------------------

/** Generates the random 256-bit vault key bytes. */
export function generateVaultKeyRaw(): Uint8Array {
  const cryptoApi = getCrypto();
  return cryptoApi.getRandomValues(new Uint8Array(32));
}

/** Imports the vault key bytes as a non-exportable AES-GCM key. */
export async function importVaultKey(rawBytes: Uint8Array): Promise<CryptoKey> {
  return makeEncKey(rawBytes, false);
}

/**
 * Wraps raw key bytes (e.g. the vault key) with a wrapping key. Works for both
 * the password wrapping key and the device key. Fresh IV per wrap.
 *
 * `aad` is optional associated data — authenticated but not encrypted. It is
 * omitted from the algorithm object entirely when undefined, so envelopes
 * written before this parameter existed (no AAD) still decrypt unchanged. A
 * caller that wraps WITH aad must unwrap WITH the same bytes; a mismatch fails
 * the GCM tag check, which is the intended "this envelope belongs to a
 * different context" signal.
 */
export async function wrapKeyBytes(
  rawBytes: Uint8Array,
  wrappingKey: CryptoKey,
  aad?: Uint8Array,
): Promise<{ iv: Uint8Array; cipher: Uint8Array }> {
  const cryptoApi = getCrypto();
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const data = Uint8Array.from(rawBytes) as Uint8Array<ArrayBuffer>;
  const cipher = await cryptoApi.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: buf(iv),
      ...(aad ? { additionalData: buf(aad) } : {}),
    },
    wrappingKey,
    data,
  );
  return {
    iv,
    cipher: new Uint8Array(cipher),
  };
}

/** Unwraps raw key bytes from a base64 ciphertext + IV envelope. */
export async function unwrapKeyBytes(
  cipherB64: string,
  ivB64: string,
  wrappingKey: CryptoKey,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const cipherBytes = fromB64(cipherB64);
  const ivBytes = fromB64(ivB64);
  const cryptoApi = getCrypto();
  const plain = await cryptoApi.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: buf(ivBytes),
      ...(aad ? { additionalData: buf(aad) } : {}),
    },
    wrappingKey,
    buf(cipherBytes),
  );
  return new Uint8Array(plain);
}

/** Generates a non-exportable AES-GCM device key. */
export async function generateDeviceKey(): Promise<CryptoKey> {
  const cryptoApi = getCrypto();
  return cryptoApi.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Derives the password wrapping key: PBKDF2 root + HKDF("vault-wrap-v2"). */
export async function derivePasswordWrappingKey(
  masterPassword: string,
  salt: string,
  iterations: number,
): Promise<CryptoKey> {
  const saltPwdBytes = fromB64(salt);
  const rootKey = await deriveRootKey(masterPassword, saltPwdBytes, iterations);
  const rawWrapBytes = await hkdfExpand(rootKey, HKDF_INFO_VAULT_WRAP, 32);
  return makeEncKey(rawWrapBytes, false);
}

// --- Auth helpers (unchanged contract) ----------------------------------

export async function createAuthKey(
  masterPassword: string,
  salt: string,
  iterations: number,
): Promise<CryptoKey> {
  const saltPwdBytes = fromB64(salt);
  const rootKey = await deriveRootKey(masterPassword, saltPwdBytes, iterations);
  const rawAuthBytes = await hkdfExpand(rootKey, HKDF_INFO_AUTH, 32);
  const authKey = await makeAuthKey(rawAuthBytes);
  return authKey;
}

/*  Vault Recovery
 vault's recovery key is a 80 byte CSPRNG secret
*/

/**
 * Recovery secret length in bytes. 160 bits is what renders as the 32-character
 * Crockford key below (160 / 5 = 32 symbols exactly, no padding bits), which is
 * the form a human can transcribe from paper without error.
 */
export const RECOVERY_SECRET_BYTES = 20;

/** Characters in a formatted recovery key (8 groups of 4, excluding dashes). */
export const RECOVERY_KEY_CHARS = 32;

/** HKDF info label for the recovery wrapping key. */
export const RECOVERY_WRAP_INFO = "recovery-wrap-v2";

/**
 * HMAC labels. These strings are part of the wire contract with the server and
 * must never change once a vault exists — a rename silently breaks recovery for
 * every vault already wrapped under the old label. Pinned by known-answer
 * tests in test/crypto-recovery.test.ts.
 */
export const RECOVERY_VERIFY_LABEL = "recovery-verify-v1";
export const RECOVERY_PROOF_LABEL = "recovery-proof-v1";

/**
 * Crockford base32: digits plus uppercase letters, excluding I, L, O and U.
 * Excluding them removes the two visual-confusion pairs (1/I/L, 0/O) and one
 * accidental-obscenity class from anything the user has to read back off paper.
 * `U` is excluded by the spec but deliberately has no decode alias below — a key
 * containing U was never issued, so it should be rejected as a typo.
 */
const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const CROCKFORD_DECODE: Record<string, number> = (() => {
  const map: Record<string, number> = {};
  for (let i = 0; i < CROCKFORD_ALPHABET.length; i += 1) {
    map[CROCKFORD_ALPHABET[i]] = i;
  }
  // Crockford's tolerance for hand transcription: I and L read as 1, O as 0.
  map.I = map["1"];
  map.L = map["1"];
  map.O = map["0"];
  return map;
})();

/** Generates the random 160-bit recovery secret. */
export function generateRecoverySecret(): Uint8Array {
  const cryptoApi = getCrypto();
  return cryptoApi.getRandomValues(new Uint8Array(RECOVERY_SECRET_BYTES));
}

/**
 * Renders recovery secret bytes as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
 *
 * There is deliberately no checksum digit: AES-GCM authentication of the
 * wrapped vault key is the verifier, so a mistyped key fails at unwrap. Adding
 * a separate checksum would give the user one more thing to mistype while
 * retyping from paper, without adding any real guarantee.
 */
export function formatRecoveryKey(bytes: Uint8Array): string {
  if (bytes.length !== RECOVERY_SECRET_BYTES) {
    throw new Error(
      `Recovery key must be ${RECOVERY_SECRET_BYTES} bytes, got ${bytes.length}.`,
    );
  }

  // Walk the byte stream 5 bits at a time, masking off consumed bits each round
  // so the accumulator can never overflow past 32 bits.
  let bits = 0;
  let bitCount = 0;
  let out = "";
  for (const byte of bytes) {
    bits = (bits << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      out += CROCKFORD_ALPHABET[(bits >> bitCount) & 31];
    }
    bits &= (1 << bitCount) - 1;
  }

  return out.replace(/(.{4})(?=.)/g, "$1-");
}

/**
 * Parses a user-typed recovery key back into secret bytes.
 *
 * Tolerates the transcription noise a human introduces when reading 32
 * characters off paper: lowercase, dashes or spaces anywhere, and the ambiguous
 * I/L -> 1 and O -> 0 substitutions. Anything else throws — including a key of
 * the wrong length, which is the mistake that must never silently truncate into
 * a different, valid-looking secret.
 */
export function parseRecoveryKey(input: string): Uint8Array {
  const normalized = input.trim().toUpperCase().replace(/[\s-]/g, "");
  if (normalized.length !== RECOVERY_KEY_CHARS) {
    throw new Error(
      `Recovery key must be ${RECOVERY_KEY_CHARS} characters, got ${normalized.length}.`,
    );
  }

  const out = new Uint8Array(RECOVERY_SECRET_BYTES);
  let bits = 0;
  let bitCount = 0;
  let byteIndex = 0;
  for (const ch of normalized) {
    const value = CROCKFORD_DECODE[ch];
    if (value === undefined) {
      throw new Error(`Invalid recovery key character "${ch}".`);
    }
    bits = (bits << 5) | value;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      out[byteIndex] = (bits >> bitCount) & 0xff;
      byteIndex += 1;
    }
    bits &= (1 << bitCount) - 1;
  }

  // Unreachable given the length check above (32 chars x 5 bits = exactly 160
  // bits = 20 bytes), but asserted so a future alphabet change cannot silently
  // return a short buffer.
  if (byteIndex !== RECOVERY_SECRET_BYTES) {
    throw new Error("Recovery key did not decode to the expected length.");
  }
  return out;
}

/**
 * K_rec = HKDF-SHA256(ikm=recoverySecret, salt=recoverySalt, info).
 *
 * Returns the AES-GCM key used to wrap and unwrap `vaultKeyRaw`. The same K_rec
 * bytes also key `computeRecoveryVerifier`, which re-derives them from the same
 * three inputs — WebCrypto fixes a CryptoKey's algorithm at import time, so one
 * key object cannot be both an AES-GCM and an HMAC key. Deterministic and
 * side-effect free: the two derivations always agree.
 */
export async function deriveRecoveryWrapKey(
  secret: Uint8Array,
  salt: string,
  info: string = RECOVERY_WRAP_INFO,
): Promise<CryptoKey> {
  const rawWrapBytes = await hkdfExpand(secret, info, 32, fromB64(salt));
  return makeEncKey(rawWrapBytes, false);
}

/**
 * recovery_verifier = HMAC-SHA256(K_rec, "recovery-verify-v1").
 *
 * This is the second authentication path that lets the server validate a
 * recovery attempt without ever seeing the secret. Unlike `vault_verifier` it is
 * derived from a 160-bit CSPRNG secret rather than a password, so a database
 * dump yields nothing to brute force, and it is only ever presented as a
 * challenge-bound proof (see `computeRecoveryProof`) — never as a static,
 * replayable credential.
 */
export async function computeRecoveryVerifier(
  secret: Uint8Array,
  salt: string,
  info: string = RECOVERY_WRAP_INFO,
): Promise<Uint8Array> {
  const rawKRec = await hkdfExpand(secret, info, 32, fromB64(salt));
  const hmacKey = await makeAuthKey(rawKRec);
  return signHmac(hmacKey, encoder.encode(RECOVERY_VERIFY_LABEL));
}

/**
 * proof = HMAC-SHA256(recovery_verifier, "recovery-proof-v1|" + vaultId + challenge).
 *
 * Binding both the vault id and a fresh server challenge is what makes this
 * non-replayable: a proof captured for one challenge cannot be reused for
 * another, and a proof for one vault cannot be presented against another. The
 * server holds `recovery_verifier` and recomputes this expected value itself,
 * so it can verify a recovery attempt while still holding neither the secret
 * nor K_rec.
 */
export async function computeRecoveryProof(
  verifier: Uint8Array,
  vaultId: string,
  challenge: string,
): Promise<Uint8Array> {
  const hmacKey = await makeAuthKey(verifier);
  const message = `${RECOVERY_PROOF_LABEL}|${vaultId}|${challenge}`;
  return signHmac(hmacKey, encoder.encode(message));
}

/**
 * Associated data binding a recovery envelope to the one vault that owns it:
 * utf8("voult-env|v2|" + vaultId + "|recovery").
 *
 * Recovery introduces a second envelope type, which turns the pre-existing
 * absence of AAD (a deferred P2 in the roadmap) into a live risk: without it, a
 * `recovery_wrap` row could be transplanted onto another vault's row and would
 * decrypt there perfectly. GCM authenticates this string, so a transplanted
 * envelope fails to unwrap. Only the recovery wrap uses AAD for now; the
 * password and device wraps pick it up in the P2 follow-up.
 */
export function recoveryAad(vaultId: string): Uint8Array {
  return encoder.encode(`voult-env|v2|${vaultId}|recovery`);
}
