// Tests for the password KDF profiles.
//
// The pinned vectors below were produced with node:crypto's argon2 (an
// implementation independent of @noble/hashes). They pin the exact Argon2id
// parameters of each ladder rung: changing m/t/p, the output length, the salt
// encoding, or the password encoding would change every derived key and make
// every existing vault unopenable.
//
// Where node:crypto.argon2 is available the suite also cross-checks noble
// against it on random inputs. When it is absent (Node < 24.7) that test skips
// with a reason rather than failing — the same pattern the recovery-PDF tests
// use for poppler/Ghostscript.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as nodeCrypto from "node:crypto";

import {
  DEFAULT_KDF,
  KDF_FLOOR,
  KDF_LADDER,
  KDF_LADDER_VERSION,
  KDF_SALT_BYTES,
  UnknownKdfProfileError,
  calibrateKdf,
  derivePasswordRoot,
  describeKdf,
  isKdfParams,
  isKnownKdf,
  kdfRank,
} from "../src/kdf.js";
import { b64, derivePasswordKeys } from "../src/crypto.js";

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// Fixed, human-checkable inputs. The salt is bytes 0x00..0x0f, which is also
// what the base64 string below decodes to.
const PASSWORD = "correct horse battery staple";
const SALT_BYTES = new Uint8Array(16).map((_, i) => i);
const SALT_B64 = "AAECAwQFBgcICQoLDA0ODw==";

// Generated once with node:crypto.argon2, then committed. Keeping constants
// here means the regression gate does not depend on the Node version.
const PINNED = [
  {
    kdf: KDF_LADDER[0],
    hex: "818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085",
  },
  {
    kdf: KDF_LADDER[1],
    hex: "bbe4ce725d8b1ae6f8c3f70b21dac67681bf71b53ffc4b805c35e6faa4477eab",
  },
  {
    kdf: KDF_LADDER[2],
    hex: "0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e",
  },
];

describe("KDF ladder", () => {
  it("is append-ordered, cheapest first, with p=1 and a 16-byte salt", () => {
    assert.ok(KDF_LADDER.length >= 3);
    assert.equal(KDF_LADDER_VERSION, 1);
    assert.equal(KDF_SALT_BYTES, 16);
    assert.deepEqual(DEFAULT_KDF, KDF_LADDER[1]);

    let previousCost = 0;
    for (const rung of KDF_LADDER) {
      assert.equal(rung.algorithm, "argon2id");
      assert.equal(rung.parallelism, 1);
      const cost = rung.memory_kib * rung.time_cost;
      assert.ok(cost > previousCost, "ladder must be monotonic in cost");
      previousCost = cost;
    }
  });

  it("matches the pinned node:crypto vectors for every rung", async () => {
    for (const { kdf, hex } of PINNED) {
      const root = await derivePasswordRoot(PASSWORD, SALT_B64, kdf);
      assert.equal(toHex(root), hex, `vector mismatch for ${describeKdf(kdf)}`);
    }
  });

  it("cross-checks @noble/hashes against node:crypto when available", async (t) => {
    const argon2Sync = (
      nodeCrypto as unknown as {
        argon2Sync?: (
          algorithm: string,
          parameters: {
            message: Uint8Array;
            nonce: Uint8Array;
            parallelism: number;
            tagLength: number;
            memory: number;
            passes: number;
          },
        ) => Buffer;
      }
    ).argon2Sync;

    if (typeof argon2Sync !== "function") {
      t.skip("node:crypto.argon2 is unavailable on this Node version");
      return;
    }

    for (const rung of KDF_LADDER) {
      const noble = await derivePasswordRoot(PASSWORD, SALT_B64, rung);
      const native = argon2Sync("argon2id", {
        message: new TextEncoder().encode(PASSWORD),
        nonce: SALT_BYTES,
        parallelism: rung.parallelism,
        tagLength: 32,
        memory: rung.memory_kib,
        passes: rung.time_cost,
      });
      assert.equal(toHex(noble), native.toString("hex"), describeKdf(rung));
    }
  });

  it("ranks only exact ladder tuples", () => {
    assert.equal(kdfRank(KDF_LADDER[0]), 1);
    assert.equal(kdfRank(KDF_LADDER[1]), 2);
    assert.equal(kdfRank(KDF_LADDER[2]), 3);
    assert.equal(kdfRank({ ...KDF_FLOOR, memory_kib: KDF_FLOOR.memory_kib + 1 }), 0);
    assert.equal(kdfRank({ ...KDF_FLOOR, parallelism: 2 }), 0);
    assert.equal(kdfRank({ algorithm: "pbkdf2-sha256", iterations: 60_000 }), 0);
    assert.equal(kdfRank(null), 0);
  });

  it("rejects malformed and off-ladder descriptors before deriving", async () => {
    const bad: unknown[] = [
      null,
      {},
      { algorithm: "pbkdf2-sha256", iterations: 60_000 },
      { ...KDF_FLOOR, memory_kib: 2 ** 31 },
      { ...KDF_FLOOR, memory_kib: 19_457 },
      { ...KDF_FLOOR, parallelism: 4 },
      { ...KDF_FLOOR, time_cost: 2.5 },
      { ...KDF_FLOOR, time_cost: "2" },
    ];

    for (const value of bad) {
      assert.equal(isKdfParams(value) && isKnownKdf(value), false, JSON.stringify(value));
      await assert.rejects(
        () => derivePasswordRoot(PASSWORD, SALT_B64, value as never),
        UnknownKdfProfileError,
      );
    }
  });

  it("rejects a salt that is not 16 bytes", async () => {
    await assert.rejects(
      () => derivePasswordRoot(PASSWORD, b64(new Uint8Array(15)), KDF_FLOOR),
      /KDF salt must be 16 bytes/,
    );
  });
});

describe("KDF calibration", () => {
  it("never returns below the floor", async () => {
    const { kdf, measuredMs } = await calibrateKdf({ budgetMs: 0 });
    assert.deepEqual(kdf, KDF_FLOOR);
    assert.ok(measuredMs >= 0);
  });

  it("picks the top rung when the budget is generous", async () => {
    const { kdf } = await calibrateKdf({ budgetMs: 60_000 });
    assert.deepEqual(kdf, KDF_LADDER[KDF_LADDER.length - 1]);
  });

  it("only ever returns a ladder member", async () => {
    for (const budgetMs of [1, 50, 150, 400, 2_000]) {
      const { kdf } = await calibrateKdf({ budgetMs });
      assert.ok(isKnownKdf(kdf), `budget ${budgetMs} returned an off-ladder profile`);
    }
  });
});

describe("derivePasswordKeys", () => {
  it("derives both keys and the verifier from one root", async () => {
    const first = await derivePasswordKeys(PASSWORD, SALT_B64, KDF_FLOOR);
    const second = await derivePasswordKeys(PASSWORD, SALT_B64, KDF_FLOOR);

    assert.equal(first.vaultVerifier, second.vaultVerifier);
    assert.notEqual(first.vaultVerifier, "");
    // A different profile is a different root, so the verifier must differ.
    const other = await derivePasswordKeys(PASSWORD, SALT_B64, KDF_LADDER[1]);
    assert.notEqual(other.vaultVerifier, first.vaultVerifier);
  });
});
