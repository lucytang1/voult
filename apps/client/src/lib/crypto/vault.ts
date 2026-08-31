// Vault identity and versioned document/package helpers (Phase 1).
// See plans/google-drive-cloud-sync.md §3.1-3.3
//
// vault_id is the portable vault identity: cryptographically random UUID v4,
// never derived from email/password/device/Google file id. One vault_id maps
// to one encrypted vault across devices/providers and is the sole local
// isolation key for storage and session authorization.

import { v4 as uuidv4 } from "uuid";
import type { VaultItem } from "../state/type";
import { VaultItemSchema } from "../state/type";

// Portable format versions. Bump when the encrypted payload structure changes.
export const VAULT_FORMAT_VERSION = 1;
export const PACKAGE_FORMAT_VERSION = 1;

// UUID v4 validation – the pattern used for vault_id throughout.
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidVaultId(vaultId: string): boolean {
  return UUID_PATTERN.test(vaultId);
}

export function assertValidVaultId(vaultId: string): void {
  if (!isValidVaultId(vaultId)) {
    throw new Error(`Invalid vault_id: ${vaultId}`);
  }
}

/**
 * Generates a new portable vault_id using a cryptographically secure random
 * UUID. Must not be derived from email/password/device/Google IDs.
 */
export function generateVaultId(): string {
  // uuidv4 uses crypto.getRandomValues when available.
  const id = uuidv4();
  // Defense in depth: ensure it matches expected pattern.
  assertValidVaultId(id);
  return id;
}

// --- Versioned vault document -----------------------------------------------
// Plaintext form that is encrypted with the vault key. The vaultId is embedded
// inside the plaintext and validated after decryption so a package cannot be
// silently copied between vault identities (see §3.3). Future providers will
// also bind vaultId as AES-GCM AAD.

export interface VaultDocument {
  formatVersion: number;
  vaultId: string;
  items: VaultItem[];
}

export function createEmptyVaultDocument(vaultId: string): VaultDocument {
  assertValidVaultId(vaultId);
  return { formatVersion: VAULT_FORMAT_VERSION, vaultId, items: [] };
}

export function serializeVaultDocument(doc: VaultDocument): string {
  assertValidVaultId(doc.vaultId);
  if (doc.formatVersion !== VAULT_FORMAT_VERSION) {
    throw new Error(`Unsupported vault formatVersion: ${doc.formatVersion}`);
  }
  // Validate items eagerly so a corrupt doc never gets encrypted.
  for (const item of doc.items) {
    const parsed = VaultItemSchema.safeParse(item);
    if (!parsed.success) {
      throw new Error(`Invalid VaultItem in document: ${parsed.error.message}`);
    }
  }
  return JSON.stringify(doc);
}

export function deserializeVaultDocument(plain: string): VaultDocument {
  const parsed = JSON.parse(plain) as { formatVersion?: unknown; vaultId?: unknown; items?: unknown };
  if (parsed.formatVersion !== VAULT_FORMAT_VERSION) {
    throw new Error(`Unsupported vault formatVersion: ${String(parsed.formatVersion)}`);
  }
  if (typeof parsed.vaultId !== "string" || !isValidVaultId(parsed.vaultId)) {
    throw new Error(`Vault document has invalid vaultId`);
  }
  const items = Array.isArray(parsed.items) ? parsed.items : [];
  // Validate each item; quarantine callers should handle errors upstream, but
  // fail fast here to avoid persisting corrupt data.
  const validItems: VaultItem[] = [];
  for (const raw of items) {
    const result = VaultItemSchema.safeParse(raw);
    if (!result.success) {
      throw new Error(`Vault document contains invalid VaultItem: ${result.error.message}`);
    }
    validItems.push(result.data);
  }
  return { formatVersion: parsed.formatVersion, vaultId: parsed.vaultId, items: validItems };
}

/**
 * Validates that the decrypted vault document's embedded vaultId matches the
 * expected vaultId (from the package metadata or local binding). Throws on
 * mismatch so the caller never hydrates a vault under the wrong identity.
 */
export function assertVaultDocumentMatches(doc: VaultDocument, expectedVaultId: string): void {
  assertValidVaultId(expectedVaultId);
  if (doc.vaultId !== expectedVaultId) {
    throw new Error(`Vault document vaultId mismatch: expected ${expectedVaultId}, got ${doc.vaultId}`);
  }
}

// --- Versioned encrypted package (conceptual, Phase 1 local shape) -----------
// The current local server stores {vault, vaultiv, salt, iterations, ...}
// per vault row. The package type here models the future cloud package so
// client code can adopt vaultId-aware flows now. Serialization stays JSON.

export interface CryptoParameters {
  salt: string;
  iterations: number;
}

export interface VoultPackage {
  packageFormatVersion: number;
  vaultId: string;
  logicalRevision: number;
  cryptoVersion: number;
  cryptoParameters: CryptoParameters;
  snapshot: { ciphertext: string; iv: string };
  passwordKeyEnvelope: { wrappedVaultKey: string; iv: string };
  // Integrity: the snapshot plaintext must contain the same vaultId and be
  // decryptable with the unwrapped vault key; AAD binding can be added later.
}

export function createVoultPackage(args: {
  vaultId: string;
  logicalRevision: number;
  cryptoVersion: number;
  salt: string;
  iterations: number;
  ciphertext: string;
  iv: string;
  wrappedVaultKey: string;
  wrappedVaultKeyIv: string;
}): VoultPackage {
  assertValidVaultId(args.vaultId);
  return {
    packageFormatVersion: PACKAGE_FORMAT_VERSION,
    vaultId: args.vaultId,
    logicalRevision: args.logicalRevision,
    cryptoVersion: args.cryptoVersion,
    cryptoParameters: { salt: args.salt, iterations: args.iterations },
    snapshot: { ciphertext: args.ciphertext, iv: args.iv },
    passwordKeyEnvelope: { wrappedVaultKey: args.wrappedVaultKey, iv: args.wrappedVaultKeyIv },
  };
}
