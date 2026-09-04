// Deterministic vault merge — intent replay onto a server snapshot.
//
// Policy (see apps/client/conflict-resolution.md §5):
//  - create: idempotent no-op when id exists; concurrent same-natural-key
//    creates keep both (no silent data loss)
//  - update: per-field LWW onto items that still exist; updates of deleted
//    items are dropped (deletes are sticky, no resurrection)
//  - delete: no-op when already absent (idempotent)
//  - undecryptable / unparseable / unknown ops are quarantined, never abort
//    the whole sync for one bad intent.
//
// Deliberately dependency-free apart from schema + crypto: no SQLite imports
// (the web app adapts its intent rows to PendingIntent; the extension builds
// them from its own queue). No secret logging — ids and ops only.

import {
  CreateVaultItemSchema,
  DeleteVaultItemSchema,
  UpdateVaultItemSchema,
  type DeleteVaultItem,
  type UpdateVaultItem,
  type VaultItem,
} from "./schema.js";
import { decrypt } from "./crypto.js";

/** Structural intent shape — both SQLite rows and extension queue items fit. */
export interface PendingIntent {
  id: string;
  operation: string;
  payload: string;
  payload_iv: string;
  created_at: string;
}

export type MergeVaultResult = {
  /** The merged vault, ready to be encrypted and pushed. */
  items: VaultItem[];
  /** Intents that were resolved (applied / no-op / dropped). */
  resolvedIds: string[];
  /** Intents that could not be applied and must be quarantined. */
  quarantinedIds: string[];
  /** Whether the vault actually changed and needs to be pushed. */
  changed: boolean;
};

type IntentOutcome = "applied" | "noop" | "dropped";

// Idempotent: a create for an id already present (e.g. replayed after a lost
// response) is a no-op. Concurrent creates of the same natural key both
// survive rather than silently dropping data.
const applyCreate = (
  items: Map<string, VaultItem>,
  item: VaultItem,
): IntentOutcome => {
  if (items.has(item.id)) return "noop";
  for (const existing of items.values()) {
    if (
      existing.id !== item.id &&
      existing.site === item.site &&
      existing.username === item.username
    ) {
      // No identifying data logged: natural-key dups are routine, not errors.
      console.warn("Duplicate natural key created concurrently; keeping both");
      break;
    }
  }
  items.set(item.id, item);
  return "applied";
};

// Per-field last-write-wins on items that still exist. An update targeting an
// item another device deleted is dropped — deletes are sticky.
const applyUpdate = (
  items: Map<string, VaultItem>,
  payload: UpdateVaultItem,
): IntentOutcome => {
  const existing = items.get(payload.id);
  if (!existing) {
    return "dropped";
  }
  items.set(payload.id, { ...existing, ...payload.fields });
  return "applied";
};

const applyDelete = (items: Map<string, VaultItem>, id: string): IntentOutcome => {
  if (!items.has(id)) return "noop";
  items.delete(id);
  return "applied";
};

// Replays pending intents onto the server snapshot in deterministic order
// (created_at asc, then id asc for ties). Returns the merged vault.
export async function mergeVault(
  serverItems: VaultItem[],
  pendingIntents: PendingIntent[],
  encKey: CryptoKey,
): Promise<MergeVaultResult> {
  const items = new Map(serverItems.map((item) => [item.id, item]));
  const resolvedIds: string[] = [];
  const quarantinedIds: string[] = [];
  let changed = false;

  const ordered = [...pendingIntents].sort(
    (a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id),
  );

  for (const intent of ordered) {
    let plaintext: string;
    try {
      plaintext = await decrypt(intent.payload, intent.payload_iv, encKey);
    } catch (error) {
      console.error("Failed to decrypt intent payload", intent.id, error);
      quarantinedIds.push(intent.id);
      continue;
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(plaintext);
    } catch (error) {
      console.error("Failed to JSON parse intent payload", intent.id, error);
      quarantinedIds.push(intent.id);
      continue;
    }

    let outcome: IntentOutcome;
    switch (intent.operation) {
      case "create": {
        const parsed = CreateVaultItemSchema.safeParse(parsedJson);
        if (!parsed.success) {
          console.error("Failed to parse create intent payload", intent.id, parsed.error);
          quarantinedIds.push(intent.id);
          continue;
        }
        outcome = applyCreate(items, parsed.data);
        break;
      }
      case "update": {
        const parsed = UpdateVaultItemSchema.safeParse(parsedJson);
        if (!parsed.success) {
          console.error("Failed to parse update intent payload", intent.id, parsed.error);
          quarantinedIds.push(intent.id);
          continue;
        }
        outcome = applyUpdate(items, parsed.data);
        break;
      }
      case "delete": {
        const parsed = DeleteVaultItemSchema.safeParse(parsedJson);
        if (!parsed.success) {
          console.error("Failed to parse delete intent payload", intent.id, parsed.error);
          quarantinedIds.push(intent.id);
          continue;
        }
        const payload: DeleteVaultItem = parsed.data;
        outcome = applyDelete(items, payload.id);
        break;
      }
      default:
        console.error("Unknown intent operation", intent.id, intent.operation);
        quarantinedIds.push(intent.id);
        continue;
    }

    if (outcome === "applied") {
      changed = true;
    } else if (outcome === "dropped") {
      console.warn("Dropped intent; item no longer exists on server", intent.id);
    }
    resolvedIds.push(intent.id);
  }

  return { items: [...items.values()], resolvedIds, quarantinedIds, changed };
}
