import {
  CRYPTO_VERSION,
  PBKDF2_ITERATIONS,
  b64,
  createAuthKey,
  decrypt,
  derivePasswordWrappingKey,
  getAuthVerifierB64,
  importVaultKey,
  unwrapKeyBytes,
  wrapKeyBytes,
} from "../crypto/index.web";
import {
  getDeviceEnvelope,
  getDeviceKey,
  getOrCreateDeviceKey,
  saveDeviceEnvelope,
} from "../crypto/device-key";
import { fetchSession } from "../queries/session/query";
import { fetchVault } from "../queries/vault/query";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import { login } from "../queries/logIn/query";
import type { LoginResponse } from "../queries/logIn/api.schema";
import {
  getVaultState,
  selectVaultSession,
  commitVaultUnlock,
  useAppStore,
} from "../state";
import { derivePasswordKeys as deriveVerifier } from "./utils";
import type { SessionState, DecryptedVault, VaultItem } from "../state/type";

export interface UnlockedSession {
  session: SessionState;
  vaultKey: CryptoKey;
  decryptedVault: DecryptedVault;
  version: number;
  // Server lock_epoch observed at unlock time (see POST /api/lock).
  lockEpoch: number;
}

function parseVaultJson(plain: string, vaultId: string): DecryptedVault {
  const parsed = JSON.parse(plain) as { items?: VaultItem[] };
  return { formatVersion: 1, vaultId, items: parsed.items ?? [] };
}

/** Derive the vaultVerifier + password wrapping key for a password. */
async function derivePasswordKeys(password: string, salt: string, iterations: number) {
  const authKey = await createAuthKey(password, salt, iterations);
  const wrappingKey = await derivePasswordWrappingKey(password, salt, iterations);
  const vaultVerifier = await getAuthVerifierB64(authKey);
  return { authKey, wrappingKey, vaultVerifier };
}

/** Wrap the vault key with the persisted browser device key and store the envelope locally. */
async function persistDeviceEnvelope(vaultKeyRaw: Uint8Array, vaultId: string) {
  const device = await getOrCreateDeviceKey(vaultId);
  const { cipher, iv } = await wrapKeyBytes(vaultKeyRaw, device.key);
  await saveDeviceEnvelope(vaultId, {
    device_id: device.device_id,
    wrapped_vault_key: b64(cipher),
    wrapped_vault_key_iv: b64(iv),
    crypto_version: CRYPTO_VERSION,
  });
}


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
 * password wrapping key locally from the master password + salt/iterations,
 * then unwraps the vault key. Wrong passwords fail at AES-GCM unwrap (throws) —
 * no server verification needed, so nothing about the attempt leaves the
 * device.
 *
 * Prefers the lock metadata captured in memory at lock time; if unavailable
 * (e.g. the tab reloaded), falls back to fetching crypto params + wrapped key
 * from the server using the still-valid session.
 *
 * This is the password-only *local* unwrap the plan describes: correct whenever
 * a valid session can supply the envelope. When the session is gone, use
 * `reauthenticateAndUnlock` instead — it re-establishes the session first.
 */
export async function unlockWithPassword(password: string): Promise<void> {
  if (getVaultState().status !== "locked") {
    throw new Error("Vault is not locked.");
  }
  const { session, lockMetadata } = useAppStore.getState();
  if (!session) throw new Error("No active session.");

  // Prefer metadata captured in memory at lock time so /lock needs no
  // round-trip; fall back to the server when the tab reloaded and lost it.
  const lm = lockMetadata;
  const envelope =
    lm?.salt && lm?.iterations && lm?.vaultKeyWrap && lm?.vaultKeyWrapIv
      ? {
          salt: lm.salt,
          iterations: lm.iterations,
          vaultKeyWrap: lm.vaultKeyWrap,
          vaultKeyWrapIv: lm.vaultKeyWrapIv,
        }
      : await fetchEnvelopeViaSession(session.vaultId);

  await unlockFromEnvelope(password, envelope);
}

/**
 * Fetches salt/iterations + the password-wrapped envelope using a live session.
 * Only reachable while the cookie is valid; after `SESSION_REQUIRED` the caller
 * must use `reauthenticateAndUnlock` instead.
 */
async function fetchEnvelopeViaSession(vaultId: string) {
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
    iterations: params.iterations,
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
 * begins with `GET /session` and would 401 straight away. So the master password
 * is the only route back in, and it does double duty:
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

  // 1. Re-establish the session. /auth rotates the cookie and returns the
  //    password-wrapped envelope, so this doubles as our envelope fetch.
  let auth: LoginResponse;
  try {
    const params = await fetchCryptoParams(vaultId);
    const { vaultVerifier } = await deriveVerifier(password, params.salt, params.iterations);
    auth = await login({ vault_id: vaultId, vault_verifier: vaultVerifier });
  } catch (e) {
    // A rejected verifier is the wrong-password signal. Anything else (offline,
    // server down, vault gone) is a distinct condition and must not read as
    // "wrong password", or the user retries a correct password forever.
    throw toUnlockError(e);
  }

  // The server must answer for the vault we asked about. A mismatch would
  // install one vault's key under another vault's identity.
  if (auth.vault_id !== vaultId) {
    throw new Error("Unexpected vault returned while re-authenticating.");
  }
  if (!auth.vault_key_wrap || !auth.vault_key_wrap_iv) {
    throw new Error("Vault key material unavailable for unlock.");
  }

  // 2. Adopt the now-live session (clears the "missing" status and persists the
  //    selection again), then unwrap locally.
  selectVaultSession({ vaultId: auth.vault_id, cryptoVersion: auth.crypto_version });
  await unlockFromEnvelope(password, {
    salt: auth.salt,
    iterations: auth.iterations,
    vaultKeyWrap: auth.vault_key_wrap,
    vaultKeyWrapIv: auth.vault_key_wrap_iv,
  });
}

/**
 * Shared unwrap: derive the password wrapping key, unwrap the vault key, and
 * install it against the current selection.
 *
 * The envelope values (salt/iterations/wrapped key) are all things the server
 * already holds, from lock metadata, a session fetch, or the /auth response.
 * Nothing here touches the network, and nothing but the verifier was ever sent.
 *
 * A wrong password fails at AES-GCM. That is caught and re-labelled to one
 * consistent message here, and — importantly — *before* any key is installed, so
 * a failed attempt never half-changes the vault state.
 */
async function unlockFromEnvelope(
  password: string,
  envelope: { salt: string; iterations: number; vaultKeyWrap: string; vaultKeyWrapIv: string },
): Promise<void> {
  const { salt, iterations, vaultKeyWrap, vaultKeyWrapIv } = envelope;
  const wrappingKey = await derivePasswordWrappingKey(password, salt, iterations);
  let vaultKey: CryptoKey;
  try {
    vaultKey = await importVaultKey(await unwrapKeyBytes(vaultKeyWrap, vaultKeyWrapIv, wrappingKey));
  } catch {
    throw new Error("Incorrect password.");
  }
  commitVaultUnlock(vaultKey);
  console.info("Vault unlocked with password");
  // vaultVersion is intentionally left untouched so pending sync intents
  // keep a valid base_version across lock/unlock.
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
