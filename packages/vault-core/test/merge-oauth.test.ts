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

describe("mergeVault with SSO sign-in methods", () => {
  it("creates an SSO-only item carrying provider + account", async () => {
    const marker: VaultItem = {
      id: uuid(),
      site: "example.com",
      username: "me@gmail.com",
      sso: [{ provider: "google", account: "me@gmail.com" }],
      origin: "https://example.com",
    };
    const res = await mergeVault({ name: "Test vault", items: [] }, [await intentFor("create", marker)], key);
    assert.equal(res.changed, true);
    assert.equal(res.items.length, 1);
    assert.deepEqual(res.items[0].sso, [{ provider: "google", account: "me@gmail.com" }]);
    assert.equal(res.items[0].password, undefined);
  });

  it("creates one account carrying both password and an SSO method", async () => {
    const both: VaultItem = {
      id: uuid(),
      site: "example.com",
      username: "me@acme.com",
      password: "pw-1",
      sso: [{ provider: "google", account: "me@acme.com" }],
      origin: "https://example.com",
    };
    const res = await mergeVault({ name: "Test vault", items: [] }, [await intentFor("create", both)], key);
    assert.equal(res.changed, true);
    assert.equal(res.items.length, 1);
    assert.equal(res.items[0].password, "pw-1");
    assert.deepEqual(res.items[0].sso, [{ provider: "google", account: "me@acme.com" }]);
  });

  it("updates replace the sso set via LWW", async () => {
    const base: VaultItem = {
      id: uuid(),
      site: "example.com",
      username: "me@acme.com",
      password: "pw-1",
      sso: [],
      origin: "https://example.com",
    };
    const res = await mergeVault(
      { name: "Test vault", items: [base] },
      [
        await intentFor("update", {
          id: base.id,
          fields: { sso: [{ provider: "google", account: "me@acme.com" }] },
        }),
      ],
      key,
    );
    assert.deepEqual(res.items[0].sso, [{ provider: "google", account: "me@acme.com" }]);
    // Untouched fields survive the per-field merge.
    assert.equal(res.items[0].username, "me@acme.com");
    assert.equal(res.items[0].password, "pw-1");
  });

  it("an sso entry with no account is quarantined, not applied", async () => {
    const bad = {
      id: uuid(),
      site: "example.com",
      username: "me@gmail.com",
      sso: [{ provider: "google" }],
      origin: "https://example.com",
    };
    const intent = await intentFor("create", bad);
    const res = await mergeVault({ name: "Test vault", items: [] }, [intent], key);
    assert.equal(res.changed, false);
    assert.deepEqual(res.items, []);
    assert.deepEqual(res.quarantinedIds, [intent.id]);
  });

  it("an unknown provider is quarantined, not applied", async () => {
    const bad = {
      id: uuid(),
      site: "example.com",
      username: "me@yahoo.com",
      sso: [{ provider: "yahoo", account: "me@yahoo.com" }],
      origin: "https://example.com",
    };
    const intent = await intentFor("create", bad);
    const res = await mergeVault({ name: "Test vault", items: [] }, [intent], key);
    assert.equal(res.changed, false);
    assert.deepEqual(res.items, []);
    assert.deepEqual(res.quarantinedIds, [intent.id]);
  });

  it("two accounts on one origin stay separate items (case F)", async () => {
    const personal: VaultItem = {
      id: uuid(),
      site: "notion.so",
      username: "me@gmail.com",
      sso: [{ provider: "google", account: "me@gmail.com" }],
      origin: "https://notion.so",
    };
    const work: VaultItem = {
      id: uuid(),
      site: "notion.so",
      username: "me@acme.com",
      sso: [{ provider: "google", account: "me@acme.com" }],
      origin: "https://notion.so",
    };
    const res = await mergeVault(
      { name: "Test vault", items: [] },
      [await intentFor("create", personal), await intentFor("create", work)],
      key,
    );
    assert.equal(res.items.length, 2);
    assert.deepEqual(
      res.items.map((i) => i.username).sort(),
      ["me@acme.com", "me@gmail.com"],
    );
  });
});