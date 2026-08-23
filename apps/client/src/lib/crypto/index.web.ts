const ITERATIONS = 60000;
import { Platform } from "react-native";

export const CRYPTO_VERSION = 2;
export const PBKDF2_ITERATIONS = ITERATIONS;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// HKDF info labels. Authentication and vault-key wrapping use distinct labels.
const HKDF_INFO_AUTH = "auth";
const HKDF_INFO_VAULT_WRAP = "vault-wrap-v2";

function getCrypto() {
    const cryptoApi = globalThis.crypto;
    if (!cryptoApi?.subtle || !cryptoApi.getRandomValues) {
        throw new Error("Web Crypto API is not available in this environment.");
    }
    return cryptoApi;
}


function generateSalt() {
    if (Platform.OS !== "web") {
        return new Uint8Array([]);
    }
    const cryptoApi = getCrypto();
    const array = new Uint8Array(16);
    cryptoApi.getRandomValues(array);
    return new Uint8Array(array);
}

export function newSaltB64() {
  return b64(generateSalt());
}

export function b64(bytes: Uint8Array) {
    return btoa(String.fromCharCode(...bytes));
}

export function fromB64(s: string) {
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function deriveRootKey(masterPassword: string, saltPwdBytes: Uint8Array, iterations: number) {
    const saltBytes = Uint8Array.from(saltPwdBytes);
    const cryptoApi = getCrypto();
    const pwKey = await cryptoApi.subtle.importKey(
      "raw",
      encoder.encode(masterPassword),
      "PBKDF2",
      false,
      ["deriveBits"]
    )

    const rootBits = await cryptoApi.subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: saltBytes,
            iterations: iterations,
        },
        pwKey,
        256
    )
    return new Uint8Array(rootBits);
}

async function hkdfExpand(rawKeyByte: Uint8Array, info: string, length: number) {
    const keyBytes = Uint8Array.from(rawKeyByte);
    const cryptoApi = getCrypto();
    const baseKey = await cryptoApi.subtle.importKey(
        "raw",
        keyBytes,
        "HKDF",
        false,
        ["deriveBits"]
    )

    const bits = await cryptoApi.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array([]), // ok if PBKDF2 already used a per user salt
          info: encoder.encode(info),
        },
        baseKey,
        length * 8
      );

      return new Uint8Array(bits);
}

async function makeEncKey(rawEncBytes: Uint8Array, extractable = false) {
    const encBytes = Uint8Array.from(rawEncBytes);
    const cryptoApi = getCrypto();
    return cryptoApi.subtle.importKey(
      "raw",
      encBytes,
      { name: "AES-GCM" },
      extractable,
      ["encrypt", "decrypt"]
    );
  }



async function makeAuthKey(rawAuthBytes: Uint8Array) {
    const authBytes = Uint8Array.from(rawAuthBytes);
    const cryptoApi = getCrypto();
    return cryptoApi.subtle.importKey(
      "raw",
      authBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
}

function concatBytes(...arrs: Uint8Array[]) {
    const len = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) {
      out.set(a, off);
      off += a.length;
    }
    return out;
}

export async function computeAuthVerifier(authKey: CryptoKey) {
    const msg = concatBytes(
      encoder.encode("auth-v1|"),
      encoder.encode("|static")
    );

    const cryptoApi = getCrypto();
    const sig = await cryptoApi.subtle.sign(
      "HMAC",
      authKey,
      msg
    );

    return new Uint8Array(sig); // 32 bytes
}

/** Returns base64 auth verifier string for API auth (e.g. get_vault user_key). */
export async function getAuthVerifierB64(authKey: CryptoKey): Promise<string> {
  const verifier = await computeAuthVerifier(authKey);
  return b64(verifier);
}

export async function encrypt(plain: string, encryptionKey: CryptoKey) {
  const cryptoApi = getCrypto();
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const cipher = await cryptoApi.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    encryptionKey,
    encoder.encode(plain)
  );
  return {
    iv,
    cipher: new Uint8Array(cipher),
  };
}

export async function decrypt(cipherB64: string, ivB64: string, encryptionKey: CryptoKey): Promise<string> {
  const cipherBytes = fromB64(cipherB64);
  const ivBytes = fromB64(ivB64);
  const cryptoApi = getCrypto();
  const plain = await cryptoApi.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    encryptionKey,
    cipherBytes
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
 * the password wrapping key and the device key.
 */
export async function wrapKeyBytes(rawBytes: Uint8Array, wrappingKey: CryptoKey) {
  const cryptoApi = getCrypto();
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(rawBytes);
  const cipher = await cryptoApi.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    wrappingKey,
    data
  );
  return {
    iv,
    cipher: new Uint8Array(cipher),
  };
}

/** Unwraps raw key bytes from a base64 ciphertext + IV envelope. */
export async function unwrapKeyBytes(cipherB64: string, ivB64: string, wrappingKey: CryptoKey): Promise<Uint8Array> {
  const cipherBytes = fromB64(cipherB64);
  const ivBytes = fromB64(ivB64);
  const cryptoApi = getCrypto();
  const plain = await cryptoApi.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    wrappingKey,
    cipherBytes
  );
  return new Uint8Array(plain);
}

/** Generates a non-exportable AES-GCM device key. */
export async function generateDeviceKey(): Promise<CryptoKey> {
  const cryptoApi = getCrypto();
  return cryptoApi.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Derives the password wrapping key: PBKDF2 root + HKDF("vault-wrap-v2"). */
export async function derivePasswordWrappingKey(masterPassword: string, salt: string, iterations: number): Promise<CryptoKey> {
  const saltPwdBytes = fromB64(salt);
  const rootKey = await deriveRootKey(masterPassword, saltPwdBytes, iterations);
  const rawWrapBytes = await hkdfExpand(rootKey, HKDF_INFO_VAULT_WRAP, 32);
  return makeEncKey(rawWrapBytes, false);
}

// --- Auth helpers (unchanged contract) ----------------------------------

export async function createAuthKey(masterPassword: string, salt: string, iterations: number): Promise<CryptoKey> {
  const saltPwdBytes = fromB64(salt);
  const rootKey = await deriveRootKey(masterPassword, saltPwdBytes, iterations);
  const rawAuthBytes = await hkdfExpand(rootKey, HKDF_INFO_AUTH, 32);
  const authKey = await makeAuthKey(rawAuthBytes);
  return authKey;
}

export async function createLoginPayload(email: string, masterPassword: string, salt: string, iterations: number) {
    const saltPwdBytes = fromB64(salt);
    const rootKey = await deriveRootKey(masterPassword, saltPwdBytes, iterations);
    const authEncBytes = await hkdfExpand(rootKey, HKDF_INFO_AUTH, 32);
    const authKey = await makeAuthKey(authEncBytes);
    const authVerifier = await computeAuthVerifier(authKey);

    return {
        email: email,
        user_key: b64(authVerifier), // send to server for comparison
    };
}
