import { sql } from "../utils";

export function upsertVaultVersion(vaultValue: number) {
  return sql(`
    INSERT OR REPLACE INTO client_state (key, value)
    VALUES (?, ?)
  `, ['vault_version', vaultValue]);
}

export function upsertDeviceId(deviceId: string) {
  return sql(`
    INSERT OR REPLACE INTO client_state (key, value)
    VALUES (?, ?)
  `, ['device_id', deviceId]);
}

export async function getlocalVaultVersion() {
  const { rows } = await sql<{ key: string; value: string }>(
    `SELECT * FROM client_state WHERE key = ?`,
    ["vault_version"],
  );
  if (!rows.length) {
    return null;
  }
  const rawValue = rows[0]?.value;
  const parsedValue = Number(rawValue);
  if (!Number.isFinite(parsedValue)) {
    console.error("Invalid local vault version in client_state", rawValue);
    return null;
  }
  return parsedValue;
}

export async function getClientStateTable() {
  const { rows } = await sql(`SELECT * FROM client_state`);
  return rows;
}

export function upsertVaultId(vaultId: string) {
  return sql(
    `INSERT OR REPLACE INTO client_state (key, value) VALUES (?, ?)`,
    ['vault_id', vaultId],
  );
}

export async function getVaultId(): Promise<string | null> {
  const { rows } = await sql<{ key: string; value: string }>(
    `SELECT * FROM client_state WHERE key = ?`,
    ["vault_id"],
  );
  return rows.length ? (rows[0]?.value ?? null) : null;
}
