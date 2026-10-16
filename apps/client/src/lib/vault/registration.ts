import { CRYPTO_VERSION } from "../crypto/index.web";
import { fetchSession } from "../queries/session/query";
import { register } from "../queries/SignUp/query";
import type { RegisterRequest, RegisterResponse } from "../queries/SignUp/api.schema";
import type { DecryptedVault } from "../state/type";
import type { UnlockedSession } from "../auth/utils";

/**
 * A vault that is completely prepared but **does not exist yet**.
 *
 * This type exists because of one invariant:
 *
 *   > A `vault` row must never exist unless its recovery file is already in the
 *   > user's hands.
 *
 * Registration and recovery setup used to be two steps with the irreversible one
 * first: `POST /register` committed the row, and only then did the user get
 * told to save a recovery file. Reload in between and you were left with a vault
 * that looks perfectly healthy, opens with the master password, and has a
 * permanently dead recovery path — `recovery/regenerate` demands proof of the
 * key that was never saved, so the key can never be reissued and the vault can
 * never be rotated. The failure was invisible until the day it mattered.
 *
 * So the order is inverted. Everything that can be derived from the master
 * password happens locally — vault id, vault key, ciphertext, password
 * envelope, recovery secret, recovery envelope, and the recovery PDF itself —
 * and the single network write happens last, after the user has the file.
 * Close the tab before that and there is nothing on the server, no session, and
 * nothing half-created.
 *
 * The same shape serves all three producers — a fresh vault, a second vault, and
 * a Drive restore — because the only thing that differs between them is where
 * the ciphertext and the vault id come from. Everything after that point is
 * identical, which is exactly what stops the three from drifting apart again.
 */
export interface PendingVaultRegistration {
  vaultId: string;
  cryptoVersion: number;
  /** Logical document version the vault starts at. */
  version: number;
  /** Exactly the body `POST /register` takes. Built once, at prepare time. */
  request: RegisterRequest;
  vaultKey: CryptoKey;
  /** Held in memory only. Zeroed by the caller once the store is wired. */
  vaultKeyRaw: Uint8Array;
  decryptedVault: DecryptedVault;
  /** Written into the one-time recovery PDF. Never rendered, never persisted. */
  recoveryKey: string;
}

export interface CommittedVault extends UnlockedSession {
  vaultKeyRaw: Uint8Array;
  recoveryKey: string;
}

/**
 * The one irreversible write, and the only network call in vault creation.
 *
 * By the time this runs the recovery file has been downloaded and confirmed, so
 * the row cannot come into existence ahead of the user's ability to recover it.
 *
 * Does NOT enrol the device key. That stays with the caller, after this
 * resolves — a device key is worth having, but it is not the artifact whose
 * absence bricks a vault.
 */
export async function commitVaultRegistration(
  pending: PendingVaultRegistration,
  sendRegistration: (payload: RegisterRequest) => Promise<RegisterResponse> = register,
): Promise<CommittedVault> {
  const response = await sendRegistration(pending.request);

  // A fresh vault starts at lock_epoch 0; read it back so the session-sync
  // check has a baseline. Best-effort — the vault is usable regardless.
  let lockEpoch = 0;
  try {
    const session = await fetchSession();
    lockEpoch = session.lock_epoch ?? 0;
  } catch {
    // Offline/legacy server — sync check converges later.
  }

  console.info("Vault registered after the recovery file was saved");

  return {
    session: {
      vaultId: response.vault_id,
      cryptoVersion: pending.cryptoVersion ?? CRYPTO_VERSION,
    },
    vaultKey: pending.vaultKey,
    decryptedVault: pending.decryptedVault,
    version: pending.version,
    lockEpoch,
    vaultKeyRaw: pending.vaultKeyRaw,
    recoveryKey: pending.recoveryKey,
  };
}

/**
 * Describes a failed commit for the screen that is about to offer a retry.
 *
 * The point of every branch here is that retrying is safe: it re-uses the SAME
 * prepared material, so a file the user already downloaded stays valid. Losing
 * the prepared state on failure would silently orphan that file — the vault
 * would come into existence under a different vault id, with a different key,
 * and the PDF in their Downloads folder would be a dead artifact that still
 * looks convincing.
 *
 * `alreadyRegistered` must be set when the register call already succeeded and
 * something later failed. Telling that user the vault "could not be created"
 * would be a lie — it exists, they hold the file, and only the local half is
 * left to redo.
 */
export function describeCommitError(
  e: unknown,
  options: { alreadyRegistered?: boolean } = {},
): string {
  const code = (e as { response?: { data?: { code?: string } } })?.response?.data?.code;
  const serverMessage = (e as { response?: { data?: { error_msg?: string } } })?.response
    ?.data?.error_msg;
  const message = (e as Error)?.message;

  if (options.alreadyRegistered) {
    return (
      "Your vault is created and your recovery file is saved, but this device could " +
      "not finish setting itself up. Press Continue to try again."
    );
  }
  if (code === "VAULT_EXISTS") {
    return "A vault with this id already exists on the server. This attempt was not saved — nothing has been changed.";
  }
  if (message && /network|fetch|timeout/i.test(message)) {
    return "Could not reach the server. Your recovery file is safe — press Continue again to retry.";
  }
  return (
    serverMessage ||
    message ||
    "Could not create the vault. Your recovery file is safe — press Continue again to retry."
  );
}