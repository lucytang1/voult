import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  IV_BYTES,
  KDF_ITERATIONS_CEILING,
  KDF_ITERATIONS_WRITE_FLOOR,
  KDF_READ_FLOOR,
  KEY_WRAP_BYTES,
  MAX_VAULT_CIPHERTEXT_BYTES,
  MIN_VAULT_CIPHERTEXT_BYTES,
  SALT_BYTES,
  SUPPORTED_CRYPTO_VERSION,
  VERIFIER_BYTES,
  KdfParamsError,
  assertKdfParams,
  assertVaultCiphertextSize,
  decodedBase64Length,
  parseBase64Bounded,
  parseBase64Exact,
} from "../src/bounds.js";

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

describe("lengths", () => {
  it("match the v2 hierarchy", () => {
    // These are the values the server also enforces; a one-sided change makes
    // every new row unreadable on the other side.
    assert.equal(SALT_BYTES, 16);
    assert.equal(IV_BYTES, 12);
    assert.equal(VERIFIER_BYTES, 32);
    assert.equal(KEY_WRAP_BYTES, 48);
    assert.equal(KDF_READ_FLOOR, KDF_ITERATIONS_WRITE_FLOOR);
    assert.equal(SUPPORTED_CRYPTO_VERSION, 2);
  });

  it("caps the ciphertext below the server body limit", () => {
    assert.ok(MIN_VAULT_CIPHERTEXT_BYTES < MAX_VAULT_CIPHERTEXT_BYTES);
    // base64 of the maximum document must fit in the server's package cap.
    assert.ok((MAX_VAULT_CIPHERTEXT_BYTES / 3) * 4 < 6 * 1024 * 1024);
  });
});

describe("canonical base64", () => {
  it("accepts canonical standard base64", () => {
    assert.equal(decodedBase64Length(""), 0);
    assert.equal(decodedBase64Length(b64(new Uint8Array(1))), 1);
    assert.equal(decodedBase64Length(b64(new Uint8Array(2))), 2);
    assert.equal(decodedBase64Length(b64(new Uint8Array(3))), 3);
    assert.equal(decodedBase64Length(b64(new Uint8Array(16))), 16);
    assert.equal(decodedBase64Length("AAAA"), 3);
    assert.equal(decodedBase64Length("AA=="), 1);
    assert.equal(decodedBase64Length("AAA="), 2);
  });

  it("rejects non-canonical forms", () => {
    // Non-zero trailing bits (the server's decoder rejects these too).
    assert.equal(decodedBase64Length("AB=="), null);
    assert.equal(decodedBase64Length("AAB="), null);
    // Unpadded, over-padded, padding in the middle.
    assert.equal(decodedBase64Length("AA"), null);
    assert.equal(decodedBase64Length("A==="), null);
    assert.equal(decodedBase64Length("===="), null);
    assert.equal(decodedBase64Length("AA=A"), null);
    // URL-safe alphabet, interior whitespace.
    assert.equal(decodedBase64Length("AA-_"), null);
    assert.equal(decodedBase64Length("AA A="), null);
    // Outer whitespace is trimmed by the public API, as on the server.
    assert.equal(decodedBase64Length("  AA==  "), 1);
  });

  it("agrees with Buffer for round-tripped bytes", () => {
    for (const len of [1, 2, 3, 4, 15, 16, 17, 32, 47, 48, 49]) {
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i += 1) bytes[i] = (i * 37 + 11) & 0xff;
      const encoded = b64(bytes);
      assert.equal(decodedBase64Length(encoded), len);
      assert.deepEqual(parseBase64Exact(encoded, len), bytes);
      assert.equal(parseBase64Exact(encoded, len + 1), null);
    }
  });

  it("bounds the decoded length", () => {
    assert.ok(parseBase64Bounded(b64(new Uint8Array(16)), 16, 16));
    assert.equal(parseBase64Bounded(b64(new Uint8Array(15)), 16, 16), null);
    assert.equal(parseBase64Bounded(b64(new Uint8Array(17)), 16, 16), null);
  });
});

describe("assertKdfParams", () => {
  it("accepts the current profile", () => {
    assert.doesNotThrow(() => assertKdfParams(SALT_BYTES, 60_000));
    assert.doesNotThrow(() => assertKdfParams(SALT_BYTES, KDF_ITERATIONS_CEILING));
  });

  it("rejects anything PBKDF2 must not be asked to do", () => {
    for (const iterations of [0, -1, 1, 59_999, KDF_ITERATIONS_CEILING + 1, 2 ** 31 - 1]) {
      assert.throws(
        () => assertKdfParams(SALT_BYTES, iterations),
        KdfParamsError,
        `iterations=${iterations} must be refused`,
      );
    }
    assert.throws(() => assertKdfParams(8, 60_000), KdfParamsError);
  });

  it("rejects non-integers", () => {
    assert.throws(() => assertKdfParams(SALT_BYTES, 60_000.5), KdfParamsError);
    assert.throws(() => assertKdfParams(SALT_BYTES, Number.NaN), KdfParamsError);
  });
});

describe("assertVaultCiphertextSize", () => {
  it("allows the cap and refuses one byte over", () => {
    assert.doesNotThrow(() => assertVaultCiphertextSize(MAX_VAULT_CIPHERTEXT_BYTES));
    assert.throws(
      () => assertVaultCiphertextSize(MAX_VAULT_CIPHERTEXT_BYTES + 1),
      /limit is/,
    );
  });
});
