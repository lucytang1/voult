import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { b64, encrypt, generateVaultKeyRaw, importVaultKey, uuid } from "../src/crypto.js";
import { mergeVault, type PendingIntent } from "../src/merge.js";
import {
  DEFAULT_FOLDER_ID,
  DEFAULT_FOLDER_NAME,
  FolderSchema,
  parseVaultDocument,
  serializeVaultDocument,
  normalizeFolderName,
  type Folder,
  type VaultItem,
} from "../src/schema.js";

let key: CryptoKey;

before(async () => {
  key = await importVaultKey(generateVaultKeyRaw());
});

const item = (over: Partial<VaultItem> = {}): VaultItem => ({
  id: uuid(),
  site: "example.com",
  username: "alice",
  password: "pw-1",
  sso: [],
  origin: "https://example.com",
  ...over,
});

const folder = (name: string, id = uuid()): Folder => ({ id, name });

const doc = (items: VaultItem[] = [], folders: Folder[] = [], name = "Test Vault") => ({
  name,
  folders,
  items,
});

async function intentFor(
  operation: string,
  payload: unknown,
  createdAt = new Date().toISOString(),
): Promise<PendingIntent> {
  const enc = await encrypt(JSON.stringify(payload), key);
  return {
    id: uuid(),
    operation,
    payload: b64(enc.cipher),
    payload_iv: b64(enc.iv),
    created_at: createdAt,
  };
}

describe("normalizeFolderName", () => {
  it("keeps capital letters (regression: the control-char class used to eat A-Z)", () => {
    assert.equal(normalizeFolderName("Test"), "Test");
    assert.equal(normalizeFolderName("WORK"), "WORK");
    assert.equal(normalizeFolderName("Personal"), "Personal");
  });

  it("collapses whitespace and strips control characters", () => {
    assert.equal(normalizeFolderName("  My   Folder  "), "My Folder");
    assert.equal(normalizeFolderName("A\u0000B\u001fC"), "ABC");
  });

  it("rejects blank and over-long names", () => {
    assert.equal(normalizeFolderName("   "), null);
    assert.equal(normalizeFolderName(""), null);
    assert.equal(normalizeFolderName("x".repeat(49)), null);
    assert.equal(normalizeFolderName(42 as unknown), null);
  });
});

describe("FolderSchema", () => {
  it("accepts the default Personal folder id", () => {
    assert.equal(
      FolderSchema.safeParse({ id: DEFAULT_FOLDER_ID, name: DEFAULT_FOLDER_NAME }).success,
      true,
    );
  });
});

describe("parseVaultDocument / serializeVaultDocument", () => {
  it("interprets a document with no folders key as one Personal folder", () => {
    const a = item();
    const parsed = parseVaultDocument(JSON.stringify({ name: "Test Vault", items: [a] }));
    assert.equal(parsed.name, "Test Vault");
    assert.deepEqual(parsed.folders, [{ id: DEFAULT_FOLDER_ID, name: DEFAULT_FOLDER_NAME }]);
    assert.equal(parsed.items[0].folderId, DEFAULT_FOLDER_ID);
  });

  it("trusts an explicitly empty folder list (does not resurrect Personal)", () => {
    const parsed = parseVaultDocument(JSON.stringify({ name: "V", folders: [], items: [] }));
    assert.deepEqual(parsed.folders, []);
  });

  it("round-trips folders and items", () => {
    const f = folder("Work");
    const a = item({ folderId: f.id });
    const parsed = parseVaultDocument(
      JSON.stringify({ name: "V", folders: [f], items: [a] }),
    );
    assert.deepEqual(parsed, { name: "V", folders: [f], items: [a] });
    assert.deepEqual(parseVaultDocument(serializeVaultDocument(parsed)), parsed);
  });

  it("never drops items when a folder entry is malformed", () => {
    const a = item();
    const parsed = parseVaultDocument(
      JSON.stringify({ name: "V", folders: [{ id: "not-a-uuid" }], items: [a] }),
    );
    assert.deepEqual(parsed.folders, []);
    assert.equal(parsed.items.length, 1);
  });
});

describe("mergeVault folder operations", () => {
  it("appends created folders and is idempotent by id", async () => {
    const f = folder("Work");
    const res = await mergeVault(
      doc(),
      [await intentFor("createFolder", f), await intentFor("createFolder", f)],
      key,
    );
    assert.equal(res.changed, true);
    assert.deepEqual(res.folders, [f]);
  });

  it("renames folders (last writer in replay order wins)", async () => {
    const f = folder("Work");
    const t1 = "2026-01-01T00:00:00.000Z";
    const t2 = "2026-01-02T00:00:00.000Z";
    const res = await mergeVault(
      doc([], [f]),
      [
        await intentFor("renameFolder", { id: f.id, name: "Office" }, t1),
        await intentFor("renameFolder", { id: f.id, name: "Job" }, t2),
      ],
      key,
    );
    assert.equal(res.folders[0].name, "Job");
  });

  it("drops a rename of a folder that no longer exists", async () => {
    const res = await mergeVault(
      doc(),
      [await intentFor("renameFolder", { id: uuid(), name: "Ghost" })],
      key,
    );
    assert.equal(res.changed, false);
    assert.deepEqual(res.resolvedIds.length, 1);
  });

  it("deleteFolder removes the folder and exactly its items", async () => {
    const f = folder("Work");
    const inFolder = item({ folderId: f.id });
    const other = item();
    const res = await mergeVault(
      doc([inFolder, other], [f]),
      [await intentFor("deleteFolder", { id: f.id })],
      key,
    );
    assert.deepEqual(res.folders, []);
    assert.deepEqual(res.items.map((i) => i.id), [other.id]);
    assert.equal(res.deletedFolderItemCount, 1);
  });

  it("keeps an item created into a deleted folder, under a dangling folderId", async () => {
    const f = folder("Work");
    const late = item({ folderId: f.id });
    const t1 = "2026-01-01T00:00:00.000Z";
    const t2 = "2026-01-02T00:00:00.000Z";
    const res = await mergeVault(
      doc([], [f]),
      [
        await intentFor("deleteFolder", { id: f.id }, t1),
        await intentFor("create", late, t2),
      ],
      key,
    );
    assert.deepEqual(res.folders, []);
    assert.equal(res.items.length, 1);
    assert.equal(res.items[0].folderId, f.id);
  });

  it("moves an item with a per-field folderId update", async () => {
    const from = folder("From");
    const to = folder("To");
    const a = item({ folderId: from.id });
    const res = await mergeVault(
      doc([a], [from, to]),
      [await intentFor("update", { id: a.id, fields: { folderId: to.id } })],
      key,
    );
    assert.equal(res.items[0].folderId, to.id);
  });
});
