// Byte helpers shared by the crypto and KDF modules.
//
// These live in their own file so `kdf.ts` can decode a salt without importing
// `crypto.ts`: `crypto.ts` delegates password-root derivation to `kdf.ts`, and
// the reverse edge would be a cycle.
//
// These are browser/worker primitives (`btoa`/`atob`), available in every
// supported runtime: the Expo web bundle, the MV3 service worker and Node.

/** Base64-encodes bytes. The wire format for salts, IVs, envelopes, keys. */
export function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/** Decodes base64. Throws on malformed input, like `atob`. */
export function fromB64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
