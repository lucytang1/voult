// Delegates to @voult/vault-core's mergeVault (single source of truth shared
// with the MV3 extension). The SQLite intent rows satisfy core's structural
// PendingIntent shape (extra columns are ignored). This also drops the old
// `site,username` warn logging — ids and ops only, per the secret-hygiene P0.
import { mergeVault } from "@voult/vault-core";
import type { MergeVaultResult } from "@voult/vault-core";
import { fetchPendingIntents } from "../sqlite/web/services/intent-service";
import { VaultItem } from "../state/type";

type PendingIntent = Awaited<ReturnType<typeof fetchPendingIntents>>[number];

export type { MergeVaultResult };

// Replays the pending intents onto the server snapshot in deterministic order
// (created_at asc, then id asc for ties). Per-op policy: see
// apps/client/conflict-resolution.md §5.
export async function mergeVaultLocal(
  serverItems: VaultItem[],
  pendingIntents: PendingIntent[],
  encKey: CryptoKey,
): Promise<MergeVaultResult> {
  return mergeVault(serverItems, pendingIntents, encKey);
}

// Keep the original name so existing import sites are untouched.
export { mergeVaultLocal as mergeVault };
