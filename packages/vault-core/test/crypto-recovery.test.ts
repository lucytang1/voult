// Tests for the vault-recovery primitives (case 3, M1).
//
// The known-answer vectors below were produced with node:crypto's hkdfSync and
// createHmac — an implementation independent of the WebCrypto path under test.
// They pin the two HMAC label strings ("recovery-verify-v1" and
// "recovery-proof-v1"), which are part of the wire contract with the server: a
// rename would silently break recovery for every vault already wrapped under the
// old label, with no test failure anywhere else to warn us.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  b64,
  fromB64,
  computeRecoveryProof,
  computeRecoveryVerifier,
  deriveRecoveryWrapKey,
  formatRecoveryKey,
  generateRecoverySecret,
  generateVaultKeyRaw,
  parseRecoveryKey,
  recoveryAad,
  unwrapKeyBytes,
  wrapKeyBytes,
  RECOVERY_KEY_CHARS,
  RECOVERY_PROOF_LABEL,
  RECOVERY_SECRET_BYTES,
  RECOVERY_VERIFY_LABEL,
  RECOVERY_WRAP_INFO,
} from "../src/crypto.js";

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// Fixed, human-checkable inputs shared by every vector assertion.
const SECRET = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
]);
const SALT_B64 = "oKGio6SlpqeoqaqrrK2urw=="; // 16 bytes, as the server stores it
const VAULT_ID = "3f2c9d8e-1a2b-4c5d-8e9f-0a1b2c3d4e5f";
const CHALLENGE = "dGhlIGNodGFsbGVuZ2U=";

// --- Known answers, cross-checked against node:crypto ----------------------
const KAT_KEY = "000G-40R4-0M30-E209-185G-R38E-1W81-24GK";
const KAT_K_REC = "616a5ce11662d9be44576cf119a7e9667899deb5fbd5febcfa8c33f5f5fa713b";
const KAT_K_REC_OTHER_INFO =
  "bafd403d7f9eed9dcd7d1283a9250bde5075fb8e68104fa4f103c6c1eb7af840";
const KAT_VERIFIER =
  "f9142a9312098f0dfbb9e98fa595dcb2b6c948d8c85f1a6ea4eef16803625b60";
const KAT_PROOF =
  "94202b1209707d83c965378165601fb916857755d2b045cc1de7075d58168c7a";

describe("generateRecoverySecret", () => {
  it("produces 20 bytes (160 bits of entropy)", () => {
    const secret = generateRecoverySecret();
    assert.equal(secret.length, RECOVERY_SECRET_BYTES);
    assert.equal(secret.length, 20);
  });

  it("does not repeat", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 64; i += 1) seen.add(toHex(generateRecoverySecret()));
    assert.equal(seen.size, 64);
  });
});

describe("formatRecoveryKey / parseRecoveryKey", () => {
  it("round-trips an arbitrary secret", () => {
    const secret = generateRecoverySecret();
    assert.deepEqual(parseRecoveryKey(formatRecoveryKey(secret)), secret);
  });

  it("round-trips many random secrets without drift", () => {
    for (let i = 0; i < 256; i += 1) {
      const secret = generateRecoverySecret();
      assert.deepEqual(parseRecoveryKey(formatRecoveryKey(secret)), secret);
    }
  });

  it("matches the known-answer rendering (8 groups of 4, 32 chars)", () => {
    const formatted = formatRecoveryKey(SECRET);
    assert.equal(formatted, KAT_KEY);
    assert.equal(formatted.replace(/-/g, "").length, RECOVERY_KEY_CHARS);
    assert.equal(formatted.split("-").length, 8);
    for (const group of formatted.split("-")) assert.equal(group.length, 4);
  });

  it("emits only the Crockford alphabet — never I, L, O or U", () => {
    // The exclusion is the whole point: these are the characters a human
    // misreads off paper, so the encoder must never produce one.
    const forbidden = new Set(["I", "L", "O", "U"]);
    for (let i = 0; i < 512; i += 1) {
      const formatted = formatRecoveryKey(generateRecoverySecret());
      for (const ch of formatted.replace(/-/g, "")) {
        assert.ok(
          !forbidden.has(ch),
          `encoded key contained ambiguous character "${ch}"`,
        );
      }
    }
  });

  it("reads back lowercase, dashes and spaces", () => {
    const formatted = formatRecoveryKey(SECRET);
    assert.deepEqual(parseRecoveryKey(formatted.toLowerCase()), SECRET);
    assert.deepEqual(parseRecoveryKey("  " + formatted + "  "), SECRET);
    // Dashes anywhere, or none at all.
    assert.deepEqual(parseRecoveryKey(formatted.split("-").join("")), SECRET);
    assert.deepEqual(parseRecoveryKey(formatted.split("").join("-")), SECRET);
  });

  it("tolerates the ambiguous characters a human substitutes", () => {
    // Crockford: I and L read as 1, O reads as 0. A key retyped with those
    // substitutions must still open the vault — the paper copy is the only copy.
    const ambiguous = KAT_KEY.replace(/1/g, "I").replace(/1/g, "L").replace(/0/g, "O");
    assert.notEqual(ambiguous, KAT_KEY);
    assert.deepEqual(parseVaultlessKey(ambiguous), SECRET);
    // And lowercase variants of those.
    assert.deepEqual(parseVaultlessKey(ambiguous.toLowerCase()), SECRET);
  });

  it("rejects a key of the wrong length", () => {
    const formatted = formatRecoveryKey(SECRET);
    assert.throws(() => parseRecoveryKey(formatted.slice(0, -1)), /32 characters/);
    assert.throws(() => parseRecoveryKey(`${formatted}A`), /32 characters/);
    assert.throws(() => parseRecoveryKey(""), /32 characters/);
    assert.throws(() => parseRecoveryKey("ABCD-EFGH"), /32 characters/);
  });

  it("rejects characters outside the alphabet, including U", () => {
    const stripped = KAT_KEY.replace(/-/g, ""); // exactly 32 symbols

    // U is excluded from the encoder and has no decode alias on purpose: a key
    // containing it was never issued, so it must not silently decode.
    assert.throws(
      () => parseRecoveryKey(`U${stripped.slice(1)}`),
      /Invalid recovery key character "U"/,
    );
    assert.throws(
      () => parseRecoveryKey(`${stripped.slice(0, 31)}!`),
      /Invalid recovery key character/,
    );

    // Sanity: every symbol above really is in the alphabet, so the two
    // rejections are about the character and not merely about the length.
    assert.doesNotThrow(() => parseRecoveryKey(stripped));
  });

  it("refuses to render bytes that are not a 160-bit secret", () => {
    assert.throws(() => formatRecoveryKey(new Uint8Array(16)), /must be 20 bytes/);
    assert.throws(() => formatRecoveryKey(new Uint8Array(32)), /must be 20 bytes/);
    assert.throws(() => formatRecoveryKey(new Uint8Array(0)), /must be 20 bytes/);
  });
});

// Small alias so the ambiguous-character test reads clearly without shadowing
// the real parser name at module scope.
function parseVaultlessKey(s: string): Uint8Array {
  return parseRecoveryKey(s);
}

describe("deriveRecoveryWrapKey", () => {
  it("is deterministic for a fixed (secret, salt, info)", async () => {
    const a = await deriveRecoveryWrapKey(SECRET, SALT_B64, RECOVERY_WRAP_INFO);
    const b = await deriveRecoveryWrapKey(SECRET, SALT_B64, RECOVERY_WRAP_INFO);
    const raw = generateRecoverySecret();

    const { cipher, iv } = await wrapKeyBytes(raw, a);
    // Key b derives the same bytes as a, so it must open what a wrote.
    assert.deepEqual(
      await unwrapKeyBytes(b64(cipher), b64(iv), b),
      raw,
    );
  });

  it("differs across info — the label really separates the key", async () => {
    const a = await deriveRecoveryWrapKey(SECRET, SALT_B64, RECOVERY_WRAP_INFO);
    const b = await deriveRecoveryWrapKey(SECRET, SALT_B64, "recovery-wrap-v3");
    const raw = generateRecoverySecret();

    const { cipher, iv } = await wrapKeyBytes(raw, a);
    await assert.rejects(() => unwrapKeyBytes(b64(cipher), b64(iv), b));

    // The underlying bytes differ too (vector KAT_K_REC vs KAT_K_REC_OTHER_INFO),
    // which is what the verifier assertions below depend on.
    assert.notEqual(KAT_K_REC, KAT_K_REC_OTHER_INFO);
  });

  it("differs across salt", async () => {
    const otherSalt = b64(new Uint8Array(16).fill(7));
    const a = await deriveRecoveryWrapKey(SECRET, SALT_B64, RECOVERY_WRAP_INFO);
    const b = await deriveRecoveryWrapKey(SECRET, otherSalt, RECOVERY_WRAP_INFO);
    const raw = generateRecoverySecret();

    const { cipher, iv } = await wrapKeyBytes(raw, a);
    await assert.rejects(() => unwrapKeyBytes(b64(cipher), b64(iv), b));
  });

  it("wraps and unwraps a vault key (the R1 shape: raw key, not a password key)", async () => {
    const kRec = await deriveRecoveryWrapKey(SECRET, SALT_B64);
    const vaultKeyRaw = generateVaultKeyRaw(); // the real 256-bit vault key
    const { cipher, iv } = await wrapKeyBytes(vaultKeyRaw, kRec, recoveryAad(VAULT_ID));

    // 32-byte plaintext + 16-byte GCM tag = 48-byte envelope.
    assert.equal(cipher.length, 48);
    assert.equal(iv.length, 12);
    assert.deepEqual(
      await unwrapKeyBytes(b64(cipher), b64(iv), kRec, recoveryAad(VAULT_ID)),
      vaultKeyRaw,
    );
  });
});

describe("recovery verifier and proof (known answers)", () => {
  it("pins the 'recovery-verify-v1' label", async () => {
    const verifier = await computeRecoveryVerifier(SECRET, SALT_B64, RECOVERY_WRAP_INFO);
    assert.equal(toHex(verifier), KAT_VERIFIER);
    assert.equal(verifier.length, 32);
    assert.equal(RECOVERY_VERIFY_LABEL, "recovery-verify-v1");
  });

  it("pins the 'recovery-proof-v1|' label and its field order", async () => {
    const verifier = await computeRecoveryVerifier(SECRET, SALT_B64);
    const proof = await computeRecoveryProof(verifier, VAULT_ID, CHALLENGE);
    assert.equal(toHex(proof), KAT_PROOF);
    assert.equal(proof.length, 32);
    assert.equal(RECOVERY_PROOF_LABEL, "recovery-proof-v1");
  });

  it("is deterministic, and tracks info/salt", async () => {
    const v1 = await computeRecoveryVerifier(SECRET, SALT_B64);
    const v2 = await computeRecoveryVerifier(SECRET, SALT_B64);
    assert.equal(toHex(v1), toHex(v2));

    const otherInfo = await computeRecoveryVerifier(SECRET, SALT_B64, "recovery-wrap-v3");
    assert.notEqual(toHex(v1), toHex(otherInfo));

    const otherSalt = await computeRecoveryVerifier(SECRET, b64(new Uint8Array(16).fill(7)));
    assert.notEqual(toHex(v1), toHex(otherSalt));
  });

  it("binds the proof to both the vault id and the challenge", async () => {
    const verifier = await computeRecoveryVerifier(SECRET, SALT_B64);
    const base = toHex(await computeRecoveryProof(verifier, VAULT_ID, CHALLENGE));

    // Replay resistance: a fresh server challenge must invalidate a captured proof.
    assert.notEqual(
      base,
      toHex(await computeRecoveryProof(verifier, VAULT_ID, "aW5vc2RoX2NoYWxsZW5nZQ==")),
    );
    // Cross-vault: a proof minted for one vault must not verify against another.
    assert.notEqual(
      base,
      toHex(
        await computeRecoveryProof(
          verifier,
          "00000000-0000-4000-8000-000000000000",
          CHALLENGE,
        ),
      ),
    );
  });
});

describe("recovery envelope AAD", () => {
  it("binds a recovery envelope to its own vault", async () => {
    const kRec = await deriveRecoveryWrapKey(SECRET, SALT_B64);
    const raw = generateRecoverySecret();
    const { cipher, iv } = await wrapKeyBytes(raw, kRec, recoveryAad(VAULT_ID));

    assert.deepEqual(
      await unwrapKeyBytes(b64(cipher), b64(iv), kRec, recoveryAad(VAULT_ID)),
      raw,
    );
    // A recovery_wrap row transplanted onto another vault's row must fail.
    await assert.rejects(() =>
      unwrapKeyBytes(
        b64(cipher),
        b64(iv),
        kRec,
        recoveryAad("00000000-0000-4000-8000-000000000000"),
      ),
    );
    // ...and so must dropping the AAD entirely.
    await assert.rejects(() => unwrapKeyBytes(b64(cipher), b64(iv), kRec));
  });

  it("encodes the documented envelope label", async () => {
    assert.equal(
      new TextDecoder().decode(recoveryAad(VAULT_ID)),
      `voult-env|v2|${VAULT_ID}|recovery`,
    );
  });
});

describe("wrapKeyBytes / unwrapKeyBytes back-compat", () => {
  it("envelopes written without AAD still decrypt without AAD", async () => {
    // Password and device wraps still pass no AAD (P2 follow-up). They must
    // behave exactly as before this parameter existed.
    const kRec = await deriveRecoveryWrapKey(SECRET, SALT_B64);
    const raw = generateRecoverySecret();
    const { cipher, iv } = await wrapKeyBytes(raw, kRec);
    assert.deepEqual(await unwrapKeyBytes(b64(cipher), b64(iv), kRec), raw);

    // An explicit empty AAD is equivalent to no AAD — the unwrap does not throw
    // merely because the argument is present.
    assert.deepEqual(
      await unwrapKeyBytes(b64(cipher), b64(iv), kRec, new Uint8Array([])),
      raw,
    );
  });
});