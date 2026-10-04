import { operation_type } from "../type";
import { sql } from "../utils";
import { v4 as uuidv4 } from "uuid";
import { useAppStore } from "@/src/lib/state";
import * as z from "zod";

export type CreateIntentPayload = {
  payload: string;
  payloadIv: string;
  deviceId: string;
};
export function createIntent(
  operation: "create" | "update" | "delete",
  payload: CreateIntentPayload,
) {
  // Fail closed: intents must only ever be written into the open per-user
  // database of the currently authenticated account.
  const session = useAppStore.getState().session;
  if (!session) {
    throw new Error("Cannot create an intent without an active session");
  }
  const id = uuidv4();
  const createdAt = new Date().toISOString();
  const baseVersion = useAppStore.getState().vaultVersion;

  // No payload logging: intent rows carry ciphertext + device identity.

  return sql(
    `
        INSERT INTO intent (id, operation, payload, payload_iv, device_id, base_version, created_at, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    `,
    [
      id,
      operation,
      payload.payload,
      payload.payloadIv,
      payload.deviceId,
      baseVersion,
      createdAt,
      null,
    ],
  );
}

const PendingIntentSchema = z.array(z.object({
  id: z.uuidv4(),
  operation: z.enum(["create", "update", "delete"]),
  payload: z.string(),
  payload_iv: z.string(),
  device_id: z.string(),
  base_version: z.number(),
  created_at: z.string(),
  synced: z.number(),
  error: z.string().nullable(),
}));


//fetches untried pending intents 
export async function fetchPendingIntents() {
  const { rows } = await sql(`SELECT * FROM intent WHERE synced = 0 AND error IS NULL ORDER BY created_at ASC`)
  const pendingIntents = PendingIntentSchema.safeParse(rows);
  if (!pendingIntents.success) {
    console.error("Failed to parse pending intents", pendingIntents.error);
    return [];
  }
  // No row logging: rows carry ciphertext + device identity.
  return pendingIntents.data;
}

export async function fetchIntents() {
  const { rows } = await sql(`SELECT * FROM intent`);
  return rows;
}

export async function markIntentsSynced(ids: string[]) {
  if (!ids.length) {
    return;
  }
  const placeholders = ids.map(() => "?").join(", ");
  await sql(
    `UPDATE intent SET synced = 1 WHERE id IN (${placeholders})`,
    ids,
  );
}

// Quarantines an intent that could not be applied (failed to decrypt/parse, or
// an unknown operation) so it stops blocking sync. fetchPendingIntents only
// returns rows where error IS NULL.
export async function markIntentError(id: string, error: string) {
  await sql(`UPDATE intent SET error = ? WHERE id = ?`, [error, id]);
}
