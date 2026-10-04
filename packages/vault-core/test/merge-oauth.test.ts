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

async function intentFor(operation: string, payload: unknown): Promise<PendingIntent> {
  const enc = await encrypt(JSON.stringify(payload), key);
  return {
    id: uuid(),
    operation,
    payload: b64(enc.cipher),
    payload_iv: b64(enc.iv),
    created_at: new Date().toISOString(),
  };
}

describe("mergeVault with SSO options", () => {
  it("creates an SSO-only item without password", async () => {
    const marker: VaultItem = {
      id: uuid(),
      site: "example.com",
      ssoProviders: ["google"],
      origin: "https://example.com",
    };
    const res = await mergeVault([], [await intentFor("create", marker)], key);
    assert.equal(res.changed, true);
    assert.equal(res.items.length, 1);
    assert.deepEqual(res.items[0].ssoProviders, ["google"]);
  });

  it("creates one item carrying both password and SSO", async () => {
    const both: VaultItem = {
      id: uuid(),
      site: "example.com",
      username: "alice",
      password: "pw-1",
      ssoProviders: ["google"],
      origin: "https://example.com",
    };
    const res = await mergeVault([], [await intentFor("create", both)], key);
    assert.equal(res.changed, true);
    assert.equal(res.items.length, 1);
    assert.equal(res.items[0].password, "pw-1");
    assert.deepEqual(res.items[0].ssoProviders, ["google"]);
  });

  it("updates replace the ssoProviders set via LWW", async () => {
    const base: VaultItem = {
      id: uuid(),
      site: "example.com",
      username: "alice",
      password: "pw-1",
      ssoProviders: [],
      origin: "https://example.com",
    };
    const res = await mergeVault(
      [base],
      [await intentFor("update", { id: base.id, fields: { ssoProviders: ["github"] } })],
      key,
    );
    assert.deepEqual(res.items[0].ssoProviders, ["github"]);
    // Untouched fields survive the per-field merge.
    assert.equal(res.items[0].username, "alice");
    assert.equal(res.items[0].password, "pw-1");
  });

  it("bad-provider creates are quarantined, not applied", async () => {
    const bad = {
      id: uuid(),
      site: "example.com",
      ssoProviders: ["yahoo"],
      origin: "https://example.com",
    };
    const intent = await intentFor("create", bad);
    const res = await mergeVault([], [intent], key);
    assert.equal(res.changed, false);
    assert.deepEqual(res.items, []);
    assert.deepEqual(res.quarantinedIds, [intent.id]);
  });
});
