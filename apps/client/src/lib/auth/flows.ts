import {
  decrypt,
  derivePasswordKeys,
  importVaultKey,
  unwrapKeyBytes,
} from "../crypto/index.web";
import { getDeviceEnvelope, getDeviceKey } from "../crypto/device-key";
import { fetchSession } from "../queries/session/query";
import { fetchVault } from "../queries/vault/query";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import { login } from "../queries/logIn/query";
import type { LoginResponse } from "../queries/logIn/api.schema";
import type { KdfParams } from "@voult/vault-core";
import { kdfEquals } from "@voult/vault-core";
import {
  getVaultState,
  selectVaultSession,
  commitVaultUnlock,
  useAppStore,
} from "../state";
import { parseVaultJson, persistDeviceSecrets } from "./utils";
import { selectedVaultId } from "../state/vault-state";
import { maybeUpgradeKdf } from "./kdf-upgrade";
import type { SessionState, DecryptedVault } from "../state/type";

export interface UnlockedSession {
  session: SessionState;
  vaultKey: CryptoKey;
  decryptedVault: DecryptedVault;
  version: number;
  // Server lock_epoch observed at unlock time (see POST /api/lock).
  lockEpoch: number;
}

/** Salt + profile + password envelope: everything needed to unwrap locally. */
interface PasswordEnvelope {
  salt: string;
  kdf: KdfParams;
  vaultKeyWrap: string;
  vaultKeyWrapIv: string;
}

/**
 * The two keys and the verifier from one root derivation. Threaded through the
 * re-auth path so `/auth` and the local unwrap do not each pay for Argon2.
 */
type DerivedCredential = {
  authKey: CryptoKey;
  wrappingKey: CryptoKey;
  vaultVerifier: string;
};

/**
 * Existing-session unlock after reload:
 * 1. Call /session using the session cookie.
 * 2. Load the local device key for this vault.
 * 3. Read the locally stored device-wrapped vault-key envelope.
 * 4. Unwrap and import the vault key locally.
 * 5. Fetch and decrypt the vault.
 *
 * Returns null when there is no valid session or the local device key /
 * envelope is missing — the caller should show the recovery/login screen.
 */
export async function unlockWithDevice(): Promise<UnlockedSession | null> {
  const sessionData = await fetchSession();
  const vaultId = sessionData.vault_id;
  // Device key + envelope are namespaced per vault, so loading by vault id
  // already prevents cross-vault unlock; the device_id match below is defense
  // in depth against a stale envelope for a re-enrolled device.
  const device = await getDeviceKey(vaultId);
  if (!device) return null;

  const envelope = await getDeviceEnvelope(vaultId);
  if (!envelope || envelope.device_id !== device.device_id) return null;

  const vaultKeyRaw = await unwrapKeyBytes(
    envelope.wrapped_vault_key,
    envelope.wrapped_vault_key_iv,
    device.key,
  );
  const vaultKey = await importVaultKey(vaultKeyRaw);

  const vaultData = await fetchVault();
  const vault = vaultData.vault;
  const plain = await decrypt(vault.vault, vault.vaultiv, vaultKey);

  return {
    session: {
      vaultId,
      cryptoVersion: vault.crypto_version,
    },
    vaultKey,
    decryptedVault: parseVaultJson(plain, vaultId),
    version: vault.version,
    lockEpoch: sessionData.lock_epoch ?? 0,
  };
}

/**
 * Unlock after a lock while the server session is still alive. Re-derives the
 * password credential locally from the master password + salt/profile, then
 * unwraps the vault key. Wrong passwords fail at AES-GCM unwrap (throws) — no
 * server verification needed, so nothing about the attempt leaves the device.
 *
 * Prefers the lock metadata captured in memory at lock time; if unavailable
 * (e.g. the tab reloaded), falls back to fetching crypto params + wrapped key
 * from the server using the still-valid session.
 *
 * If the cached metadata fails, the credential may have been rotated on another
 * device after this tab locked. One retry against fresh server state
 * distinguishes that from a genuinely wrong password: if the salt/profile are
 * unchanged, there is nothing to retry.
 */
export async function unlockWithPassword(password: string): Promise<void> {
  if (getVaultState().status !== "locked") {
    throw new Error("Vault is not locked.");
  }
  const { session, lockMetadata } = useAppStore.getState();
  if (!session) throw new Error("No active session.");

  const cached: PasswordEnvelope | null =
    lockMetadata?.salt && lockMetadata.kdf && lockMetadata.vaultKeyWrap && lockMetadata.vaultKeyWrapIv
      ? {
          salt: lockMetadata.salt,
          kdf: lockMetadata.kdf,
          vaultKeyWrap: lockMetadata.vaultKeyWrap,
          vaultKeyWrapIv: lockMetadata.vaultKeyWrapIv,
        }
      : null;

  const envelope = cached ?? (await fetchEnvelopeViaSession(session.vaultId));
  try {
    await unlockFromEnvelope(password, envelope);
  } catch (e) {
    if (!isIncorrectPassword(e)) throw e;

    // The credential may have rotated after the envelope was captured (cached
    // metadata from a previous lock, or a race between the two params requests).
    // Refetch once. If nothing changed, the password really is wrong and the
    // extra KDF is skipped.
    const fresh = await fetchEnvelopeViaSession(session.vaultId);
    const unchanged =
      fresh.salt === envelope.salt &&
      kdfEquals(fresh.kdf, envelope.kdf) &&
      fresh.vaultKeyWrap === envelope.vaultKeyWrap;
    if (unchanged) throw e;
    await unlockFromEnvelope(password, fresh);
  }
}

/**
 * Fetches salt/profile + the password-wrapped envelope using a live session.
 * Only reachable while the cookie is valid; after `SESSION_REQUIRED` the caller
 * must use `reauthenticateAndUnlock` instead.
 */
async function fetchEnvelopeViaSession(vaultId: string): Promise<PasswordEnvelope> {
  const [params, vaultData] = await Promise.all([
    fetchCryptoParams(vaultId),
    fetchVault(),
  ]);
  const vault = vaultData.vault;
  if (!vault.vault_key_wrap || !vault.vault_key_wrap_iv) {
    throw new Error("Vault key material unavailable for unlock.");
  }
  return {
    salt: params.salt,
    kdf: params.kdf,
    vaultKeyWrap: vault.vault_key_wrap,
    vaultKeyWrapIv: vault.vault_key_wrap_iv,
  };
}

/**
 * M2: unlock when the server session is gone (the vault is selected but its
 * cookie is missing or was rejected).
 *
 * The user's situation after `SESSION_REQUIRED`: they are on their own vault's
 * lock screen with no cookie. A device-key unlock cannot help here, because it
 * begins with `GET /session` and would 401 straight away. So the master
 * password is the only route back in, and it does double duty:
 *
 *   1. Re-establish the server session through the *existing* verifier flow —
 *      derive `vaultVerifier` locally, POST /auth. The master password and the
 *      vault key never leave the device; only the verifier crosses the wire.
 *   2. Unwrap the vault key locally from the envelope /auth returns.
 *
 * Step 1 is also what makes a wrong password fail safely: /auth rejects a bad
 * verifier with 401 and returns nothing usable, so we never reach the unwrap and
 * never install a key. (With a live session the wrong password instead fails
 * locally at AES-GCM — see `unlockWithPassword`.)
 *
 * Re-auth is not a silent auto-unlock: it only runs because the user typed their
 * password on the lock screen. Pairing it with `unlockWithDevice()` behind a
 * lost session would produce an unlocked UI whose API calls all 401.
 */
export async function reauthenticateAndUnlock(password: string): Promise<void> {
  const state = useAppStore.getState();
  if (state.vault.status !== "locked") {
    throw new Error("Vault is not locked.");
  }
  const vaultId = state.vault.vaultId;

  try {
    // 1. Fetch the profile, derive once, authenticate. If another device
    //    rotated the credential between the params read and /auth, refetch and
    //    retry once before calling it a wrong password.
    let params = await fetchCryptoParams(vaultId);
    let credential = await derivePasswordKeys(password, params.salt, params.kdf);

    let auth: LoginResponse;
    try {
      auth = await login({ vault_id: vaultId, vault_verifier: credential.vaultVerifier });
    } catch (e) {
      const fresh = await fetchCryptoParams(vaultId);
      if (fresh.salt === params.salt && kdfEquals(fresh.kdf, params.kdf)) throw e;
      params = fresh;
      credential = await derivePasswordKeys(password, fresh.salt, fresh.kdf);
      auth = await login({ vault_id: vaultId, vault_verifier: credential.vaultVerifier });
    }

    // The server must answer for the vault we asked about. A mismatch would
    // install one vault's key under another vault's identity.
    if (auth.vault_id !== vaultId) {
      throw new Error("Unexpected vault returned while re-authenticating.");
    }
    if (!auth.vault_key_wrap || !auth.vault_key_wrap_iv) {
      throw new Error("Vault key material unavailable for unlock.");
    }
    // The credential we derived must be the one /auth just validated. If the
    // profile moved in between, the prepared keys would unwrap nothing.
    if (auth.salt !== params.salt || !kdfEquals(auth.kdf, params.kdf)) {
      throw new Error("Vault credential changed during unlock. Try again.");
    }

    // 2. Adopt the now-live session (clears the "missing" status and persists
    //    the selection again), then unwrap locally with the keys already derived.
    selectVaultSession({ vaultId: auth.vault_id, cryptoVersion: auth.crypto_version });
    await unlockFromEnvelope(
      password,
      {
        salt: auth.salt,
        kdf: auth.kdf,
        vaultKeyWrap: auth.vault_key_wrap,
        vaultKeyWrapIv: auth.vault_key_wrap_iv,
      },
      credential,
    );
  } catch (e) {
    // A rejected verifier is the wrong-password signal. Anything else (offline,
    // server down, vault gone) is a distinct condition and must not read as
    // "wrong password", or the user retries a correct password forever.
    throw toUnlockError(e);
  }
}

/**
 * Shared unwrap: derive the password credential (unless the caller already
 * did), unwrap the vault key, and install it against the current selection.
 *
 * A wrong password fails at AES-GCM. That is caught and re-labelled to one
 * consistent message here, and — importantly — *before* any key is installed, so
 * a failed attempt never half-changes the vault state.
 */
async function unlockFromEnvelope(
  password: string,
  envelope: PasswordEnvelope,
  prepared?: DerivedCredential,
): Promise<void> {
  const { salt, kdf, vaultKeyWrap, vaultKeyWrapIv } = envelope;
  // One Argon2 run for both keys and the verifier. Never derive the auth key
  // and the wrapping key separately: at the top rung that would be two ~0.6 s
  // derivations per unlock.
  const credential = prepared ?? (await derivePasswordKeys(password, salt, kdf));
  let vaultKeyRaw: Uint8Array;
  let vaultKey: CryptoKey;
  try {
    vaultKeyRaw = await unwrapKeyBytes(vaultKeyWrap, vaultKeyWrapIv, credential.wrappingKey);
    vaultKey = await importVaultKey(vaultKeyRaw);
  } catch {
    throw new Error("Incorrect password.");
  }
  commitVaultUnlock(vaultKey);
  console.info("Vault unlocked with password");

  // (Re)establish this browser's device-wrapped envelope from the key we just
  // unwrapped. Without this, an origin whose only way in has been the master
  // password never grows an envelope: the device key exists, but
  // `unlockWithDevice()` finds nothing to unwrap, so every reload/restart falls
  // back to the lock screen even with Autolock = Never. Best-effort — the vault
  // is already open, and a storage failure only costs the next silent restore.
  const vaultId = selectedVaultId(useAppStore.getState().vault);
  if (vaultId) {
    try {
      await persistDeviceSecrets(vaultKeyRaw, vaultId);
    } catch (e) {
      console.warn("Unlocked, but could not store the device envelope", e);
    }

    // Opportunistic profile upgrade. The vault is already open; a failure is a
    // warning, never a failed unlock. The upgrade needs its own copy of the raw
    // key because this function zeroes its copy at the end.
    const upgradeKey = vaultKeyRaw.slice();
    void maybeUpgradeKdf({
      vaultId,
      password,
      currentKdf: kdf,
      currentVerifier: credential.vaultVerifier,
      vaultKeyRaw: upgradeKey,
    });
  }
  // The imported CryptoKey has copied the bytes; drop the raw copy.
  vaultKeyRaw.fill(0);

  // vaultVersion is intentionally left untouched so pending sync intents
  // keep a valid base_version across lock/unlock.
}

/** True only for the one message `unlockFromEnvelope` uses for a bad unwrap. */
function isIncorrectPassword(e: unknown): boolean {
  return e instanceof Error && e.message === "Incorrect password.";
}

/**
 * Normalize an error into one the lock screen can render honestly.
 *
 * A wrong password and an unreachable server are different problems with
 * different remedies, so they must not collapse into one message. Only an
 * explicit auth rejection is treated as a wrong password; transport failures
 * pass through with their own text.
 */
function toUnlockError(e: unknown): Error {
  const status = (e as { response?: { status?: number } })?.response?.status;
  const msg = (e as { response?: { data?: { error_msg?: string } } })?.response?.data?.error_msg;
  if (status === 401 || status === 403 || /invalid/i.test(msg ?? "")) {
    return new Error("Incorrect password.");
  }
  if (status === 404) {
    return new Error(
      "This vault is no longer available on the server. Switch to another vault or create a new one.",
    );
  }
  if (status === undefined) {
    return new Error("Cannot reach the server. Check your connection and try again.");
  }
  return new Error(msg || "Unlock failed. Please try again.");
}
