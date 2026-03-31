import { sql } from "./utils";
export async function up() {
    const result  = await sql(`
        PRAGMA journal_mode = WAL;

        CREATE TABLE IF NOT EXISTS intent (
            id TEXT PRIMARY KEY,
            operation TEXT NOT NULL,
            payload TEXT NOT NULL,
            payload_iv TEXT NOT NULL,
            device_id TEXT NOT NULL,
            base_version INTEGER,
            created_at INTEGER NOT NULL,
            synced INTEGER DEFAULT 0,
            error TEXT
        );

        CREATE TABLE IF NOT EXISTS client_state (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    `);
    return result;
}