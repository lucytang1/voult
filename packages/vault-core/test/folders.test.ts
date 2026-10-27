import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { b64, encrypt, generateVaultKeyRaw, importVaultKey, uuid } from "../src/crypto.js";
import { mergeVault, type PendingIntent } from "../src/merge.js";
import {
  DEFAULT_FOLDER_ID,
  DEFAULT_FOLDER_NAME,
  FolderSchema,
  UNFILED_LABEL,
  countByFolder,
  folderNameFor,
  itemsInFolder,
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

describe("folder view helpers", () => {
  it("names an item's live folder, and calls dangling ids Unfiled", () => {
    const work = folder("Work");
    assert.equal(folderNameFor([work], { folderId: work.id }), "Work");
    assert.equal(folderNameFor([work], { folderId: uuid() }), UNFILED_LABEL);
    assert.equal(folderNameFor([work], {}), UNFILED_LABEL);
  });

  it("puts missing and dangling folder ids in the Unfiled bucket", () => {
    const work = folder("Work");
    const filed = item({ folderId: work.id });
    const unfiled = item();
    const dangling = item({ folderId: uuid() });
    assert.deepEqual(
      itemsInFolder([filed, unfiled, dangling], [work], null).map((i) => i.id),
      [unfiled.id, dangling.id],
    );
    assert.deepEqual(
      itemsInFolder([filed, unfiled, dangling], [work], work.id).map((i) => i.id),
      [filed.id],
    );
  });

  it("counts all, unfiled, and each folder consistently", () => {
    const work = folder("Work");
    const personal = folder("Personal");
    const counts = countByFolder(
      [
        item({ folderId: work.id }),
        item({ folderId: personal.id }),
        item(),
        item({ folderId: uuid() }),
      ],
      [work, personal],
    );
    assert.deepEqual(counts, { all: 4, unfiled: 2, byId: { [work.id]: 1, [personal.id]: 1 } });
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
