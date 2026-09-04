import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import {
  b64,
  encrypt,
  generateVaultKeyRaw,
  importVaultKey,
  uuid,
} from "../src/crypto.js";
import { mergeVault, type PendingIntent } from "../src/merge.js";
import type { VaultItem } from "../src/schema.js";

let key: CryptoKey;

before(async () => {
  key = await importVaultKey(generateVaultKeyRaw());
});

const item = (over: Partial<VaultItem> = {}): VaultItem => ({
  id: uuid(),
  site: "example.com",
  username: "alice",
  password: "pw-1",
  origin: "https://example.com",
  ...over,
});

async function intentFor(operation: string, payload: unknown, createdAt = new Date().toISOString()): Promise<PendingIntent> {
  const enc = await encrypt(JSON.stringify(payload), key);
  return {
    id: uuid(),
    operation,
    payload: b64(enc.cipher),
    payload_iv: b64(enc.iv),
    created_at: createdAt,
  };
}

describe("mergeVault", () => {
  it("inserts creates", async () => {
    const fresh = item();
    const res = await mergeVault([], [await intentFor("create", fresh)], key);
    assert.equal(res.changed, true);
    assert.equal(res.items.length, 1);
    assert.deepEqual(res.items[0], fresh);
    assert.deepEqual(res.quarantinedIds, []);
  });

  it("replays of an existing id are no-ops (idempotent)", async () => {
    const fresh = item();
    const intent = await intentFor("create", fresh);
    const res = await mergeVault([fresh], [intent], key);
    assert.equal(res.changed, false);
    assert.equal(res.items.length, 1);
    assert.deepEqual(res.resolvedIds, [intent.id]);
  });

  it("concurrent same-natural-key creates keep both", async () => {
    const a = item({ id: uuid() });
    const b = item({ id: uuid(), password: "pw-2" });
    const res = await mergeVault(
      [],
      [await intentFor("create", a, "2026-01-01T00:00:00.000Z"), await intentFor("create", b, "2026-01-01T00:00:01.000Z")],
      key,
    );
    assert.equal(res.items.length, 2);
  });

  it("updates merge per-field (LWW) and preserve origin", async () => {
    const base = item();
    const res = await mergeVault(
      [base],
      [await intentFor("update", { id: base.id, fields: { password: "pw-2" } })],
      key,
    );
    assert.equal(res.changed, true);
    assert.equal(res.items[0].password, "pw-2");
    assert.equal(res.items[0].origin, "https://example.com");
    assert.equal(res.items[0].username, "alice");
  });

  it("updates of deleted items are dropped (deletes stick)", async () => {
    const res = await mergeVault(
      [],
      [await intentFor("update", { id: uuid(), fields: { password: "x" } })],
      key,
    );
    assert.equal(res.changed, false);
    assert.equal(res.items.length, 0);
  });

  it("deletes remove; deleting the absent is a no-op", async () => {
    const base = item();
    const gone = await mergeVault([base], [await intentFor("delete", { id: base.id })], key);
    assert.equal(gone.changed, true);
    assert.deepEqual(gone.items, []);
    const noop = await mergeVault([], [await intentFor("delete", { id: uuid() })], key);
    assert.equal(noop.changed, false);
  });

  it("undecryptable and malformed intents are quarantined, rest still apply", async () => {
    const good = item();
    const badDecrypt: PendingIntent = {
      id: uuid(),
      operation: "create",
      payload: "!!!not-base64!!!",
      payload_iv: b64(new Uint8Array(12)),
      created_at: new Date().toISOString(),
    };
    const enc = await encrypt("not-json{{{", key);
    const badJson: PendingIntent = {
      id: uuid(),
      operation: "create",
      payload: b64(enc.cipher),
      payload_iv: b64(enc.iv),
      created_at: new Date().toISOString(),
    };
    const res = await mergeVault([ ], [badDecrypt, badJson, await intentFor("create", good)], key);
    assert.deepEqual(new Set(res.quarantinedIds), new Set([badDecrypt.id, badJson.id]));
    assert.equal(res.items.length, 1);
    assert.equal(res.changed, true);
  });

  it("unknown operations are quarantined", async () => {
    const res = await mergeVault([], [await intentFor("rename", { id: uuid() })], key);
    assert.equal(res.quarantinedIds.length, 1);
    assert.equal(res.changed, false);
  });

  it("replays in (created_at, id) order deterministically", async () => {
    const base = item();
    const first = await intentFor("update", { id: base.id, fields: { password: "first" } }, "2026-01-01T00:00:00.000Z");
    const second = await intentFor("update", { id: base.id, fields: { password: "second" } }, "2026-01-01T00:00:01.000Z");
    const res = await mergeVault([base], [second, first], key);
    assert.equal(res.items[0].password, "second");
  });
});
