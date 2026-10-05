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

async function hkdfExpand(rawKeyByte: Uint8Array, info: string, length: number): Promise<Uint8Array> {
  const keyBytes = Uint8Array.from(rawKeyByte) as Uint8Array<ArrayBuffer>;
  const cryptoApi = getCrypto();
  const baseKey = await cryptoApi.subtle.importKey("raw", keyBytes, "HKDF", false, [
    "deriveBits",
  ]);

  const bits = await cryptoApi.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array([]), // ok: PBKDF2 already used a per-vault salt
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

export async function computeAuthVerifier(authKey: CryptoKey): Promise<Uint8Array> {
  const msg = concatBytes(encoder.encode("auth-v1|"), encoder.encode("|static"));

  const cryptoApi = getCrypto();
  const sig = await cryptoApi.subtle.sign("HMAC", authKey, buf(msg));

  return new Uint8Array(sig); // 32 bytes
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
 */
export async function wrapKeyBytes(
  rawBytes: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<{ iv: Uint8Array; cipher: Uint8Array }> {
  const cryptoApi = getCrypto();
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const data = Uint8Array.from(rawBytes) as Uint8Array<ArrayBuffer>;
  const cipher = await cryptoApi.subtle.encrypt(
    { name: "AES-GCM", iv: buf(iv) },
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
): Promise<Uint8Array> {
  const cipherBytes = fromB64(cipherB64);
  const ivBytes = fromB64(ivB64);
  const cryptoApi = getCrypto();
  const plain = await cryptoApi.subtle.decrypt(
    { name: "AES-GCM", iv: buf(ivBytes) },
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
