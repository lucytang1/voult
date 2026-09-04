// Shared vault schemas — single source of truth for VaultItem and sync ops.
//
// Change from the web app's original shape: VaultItem gains a REQUIRED
// `origin` (canonical save-time origin, e.g. "https://accounts.example.com")
// plus optional `urls` (extra linked origins). Rationale: the old
// `{site, username}` free-text pair cannot answer "does this login belong to
// this origin?", so suggest/autofill cannot be phishing-resistant without it.
// No releases exist, so this changes the schema in place: no formatVersion,
// no migration, no legacy fallback — origin-less items are invalid.

import * as z from "zod";

export const VaultItemSchema = z.object({
  id: z.uuid(),
  site: z.string(),
  username: z.string(),
  password: z.string(),
  // Canonical origin captured at save time (scheme + host [+ non-default port]).
  // Optional during the M0 transition: the web add-item form does not capture
  // it yet (M1 wires it); extension writers always set it. Items without an
  // origin are valid but never origin-matched (rankOriginMatch → null).
  origin: z.string().optional(),
  // Additional origins the user explicitly linked to this login.
  urls: z.array(z.string()).optional(),
});

export type VaultItem = z.infer<typeof VaultItemSchema>;

export const VAULT_DOCUMENT_FORMAT_VERSION = 1;

export interface DecryptedVault {
  formatVersion: number;
  vaultId: string;
  items: VaultItem[];
}

/**
 * The active session, scoped to a single vault. There is no account/user object
 * — `vaultId` is the only identity and the session cookie carries only it.
 */
export interface SessionState {
  vaultId: string;
  cryptoVersion: number;
}

/**
 * Material needed to re-derive the vault key locally when unlocking after a
 * lock. All values are zero-knowledge-safe (salt/iterations/wrapped key are
 * things the server already knows).
 */
export interface LockMetadata {
  salt: string;
  iterations: number;
  vaultKeyWrap: string;
  vaultKeyWrapIv: string;
}

/** The three top-level app states. */
export type AuthState = "not_authenticated" | "locked" | "unlocked";

// --- Sync op payloads ----------------------------------------------------
// Create carries a full VaultItem. Update carries only changed fields so two
// devices editing different fields of the same entry both survive a merge.
// Origin/urls ride the same per-field LWW path as site/username/password.

export const UpdateVaultItemSchema = z.object({
  id: z.uuid(),
  fields: z.object({
    site: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    origin: z.string().optional(),
    urls: z.array(z.string()).optional(),
  }),
});
export type UpdateVaultItem = z.infer<typeof UpdateVaultItemSchema>;

export const DeleteVaultItemSchema = z.object({
  id: z.uuid(),
});
export type DeleteVaultItem = z.infer<typeof DeleteVaultItemSchema>;

export const CreateVaultItemSchema = VaultItemSchema;
export type CreateVaultItem = z.infer<typeof CreateVaultItemSchema>;

// --- Server API shapes (shared so web + extension can't drift) ------------

export type VaultResponse = {
  vault: {
    vault: string;
    vaultiv: string;
    iterations: number;
    version: number;
    crypto_version: number;
    vault_key_wrap: string | null;
    vault_key_wrap_iv: string | null;
  };
};

export type UpdateVaultRequest = {
  vault: string;
  vaultiv: string;
  version: number;
  crypto_version?: number;
  vault_key_wrap?: string;
  vault_key_wrap_iv?: string;
};

export type UpdateVaultResponse = {
  vault: string;
  vaultiv: string;
  iterations: number;
  version: number;
  crypto_version: number;
  vault_key_wrap: string | null;
  vault_key_wrap_iv: string | null;
};
