// Client-side password-credential rotation.
//
// A KDF profile change is a *rewrap*: the vault key never moves, so the client
// derives the new verifier + wrapping key, re-wraps the same `vaultKeyRaw`, and
// proves the new envelope opens before the server write. The password and the
// key never leave the device; the server receives only a fresh salt, the
// descriptor, a verifier and ciphertext.
//
// Two callers:
//   * `maybeUpgradeKdf` after a password unlock, when this device calibrates a
//     higher rung than the vault currently uses;
//   * `upgradeVaultKdfWithPassword` from Settings, for users who normally rely
//     on the device key and therefore never type their password.

import {
  b64,
  derivePasswordKeys,
  newSaltB64,
  unwrapKeyBytes,
  wrapKeyBytes,
} from "../crypto/index.web";
import {
  DEFAULT_KDF,
  KDF_LADDER_VERSION,
  calibrateKdf,
  describeKdf,
  isKnownKdf,
  kdfRank,
} from "@voult/vault-core";
import type { KdfParams } from "@voult/vault-core";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import { fetchVault } from "../queries/vault/query";
import { rotateVaultCredential } from "../queries/vaultCredential/query";
import { queryClient } from "../queries/client";
import { setLockMetadata } from "../state";

const TARGET_STORAGE_KEY = "voult.kdfTarget.v1";

interface CachedTarget {
  ladderVersion: number;
  kdf: KdfParams;
  measuredMs: number;
}

function storage(): Storage | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    // Private mode / disabled storage: calibration simply re-runs.
    return null;
  }
}

/**
 * The device's cached calibration target, or null when it has not run (or the
 * ladder changed since it did). Non-secret: it is a public parameter tuple.
 */
export function getCachedKdfTarget(): KdfParams | null {
  const raw = storage()?.getItem(TARGET_STORAGE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<CachedTarget>;
    if (parsed.ladderVersion !== KDF_LADDER_VERSION) return null;
    return isKnownKdf(parsed.kdf) ? parsed.kdf : null;
  } catch {
    return null;
  }
}

/**
 * Returns this device's calibrated profile, running the benchmark once and
 * caching it. Never returns below the OWASP floor. If calibration itself fails
 * (no timer, a broken build), falls back to the default rung rather than
 * blocking vault creation.
 */
export async function ensureKdfTarget(): Promise<KdfParams> {
  const cached = getCachedKdfTarget();
  if (cached) return cached;

  try {
    const { kdf, measuredMs } = await calibrateKdf();
    const payload: CachedTarget = {
      ladderVersion: KDF_LADDER_VERSION,
      kdf,
      measuredMs,
    };
    storage()?.setItem(TARGET_STORAGE_KEY, JSON.stringify(payload));
    console.info(
      `Password KDF calibrated: ${describeKdf(kdf)} (${Math.round(measuredMs)} ms)`,
    );
    return kdf;
  } catch (e) {
    console.warn("KDF calibration failed; using the default profile", e);
    return DEFAULT_KDF;
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function refreshAfterRotation(vaultId: string): void {
  // Any tab holding the old salt/envelope must refetch. The in-memory lock
  // metadata is dropped too: it is only an optimisation, and a stale copy is
  // exactly what makes a correct password look wrong after a rotation.
  queryClient.invalidateQueries({ queryKey: ["cryptoParams", vaultId] });
  queryClient.invalidateQueries({ queryKey: ["vault"] });
  setLockMetadata(null);
}

/**
 * True when a failed rotation actually means "someone already installed this
 * target". A lost response arrives as 401 (the stored verifier changed); a
 * concurrent rotation arrives as 409. Both are success for our purpose if the
 * server now reports the target profile.
 */
async function convergedOnTarget(
  vaultId: string,
  target: KdfParams,
  error: unknown,
): Promise<boolean> {
  const status = (error as { response?: { status?: number } })?.response?.status;
  if (status !== 401 && status !== 409) return false;
  try {
    const params = await fetchCryptoParams(vaultId);
    // Any rung at or above the target is a success: another device may have
    // calibrated higher than this one.
    return kdfRank(params.kdf) >= kdfRank(target);
  } catch {
    return false;
  }
}

interface RotateArgs {
  vaultId: string;
  password: string;
  currentKdf: KdfParams;
  currentVerifier: string;
  vaultKeyRaw: Uint8Array;
  credentialVersion: number;
  targetKdf: KdfParams;
}

async function rotateCredential(
  args: RotateArgs,
): Promise<"rotated" | "already"> {
  const newSalt = newSaltB64();
  const next = await derivePasswordKeys(args.password, newSalt, args.targetKdf);
  const { cipher, iv } = await wrapKeyBytes(args.vaultKeyRaw, next.wrappingKey);

  // Prove the new envelope opens before the irreversible write. Same pattern as
  // recovery: a derivation or envelope bug fails for free, locally.
  const roundTrip = await unwrapKeyBytes(b64(cipher), b64(iv), next.wrappingKey);
  const matches = bytesEqual(roundTrip, args.vaultKeyRaw);
  roundTrip.fill(0);
  if (!matches) {
    throw new Error("KDF_UPGRADE_VERIFY_FAILED");
  }

  try {
    await rotateVaultCredential({
      current_vault_verifier: args.currentVerifier,
      credential_version: args.credentialVersion,
      new_salt: newSalt,
      new_kdf: args.targetKdf,
      new_vault_verifier: next.vaultVerifier,
      new_vault_key_wrap: b64(cipher),
      new_vault_key_wrap_iv: b64(iv),
    });
  } catch (e) {
    if (await convergedOnTarget(args.vaultId, args.targetKdf, e)) {
      console.info("Vault protection was already upgraded by another surface");
      refreshAfterRotation(args.vaultId);
      return "already";
    }
    throw e;
  }

  console.info(`Vault protection upgraded to ${describeKdf(args.targetKdf)}`);
  refreshAfterRotation(args.vaultId);
  return "rotated";
}

/**
 * Best-effort upgrade after a password unlock. The vault is already open, so
 * every failure is a warning — never a reason to fail the unlock. The caller
 * hands over a copy of the raw vault key and this function owns it: it is zeroed
 * when the (possibly deferred) attempt finishes.
 *
 * The work is deferred to an idle slot because it runs a second Argon2
 * derivation (and possibly a first-time calibration) on the main thread. The
 * vault is usable immediately; the upgrade should not fight the first paint.
 */
export async function maybeUpgradeKdf(args: {
  vaultId: string;
  password: string;
  currentKdf: KdfParams;
  currentVerifier: string;
  vaultKeyRaw: Uint8Array;
}): Promise<void> {
  const run = async () => {
    try {
      const target = await ensureKdfTarget();
      if (kdfRank(target) <= kdfRank(args.currentKdf)) return;

      // Read the CAS counter fresh: the caller's unlock may have raced another
      // device, and lock metadata is not authoritative for it.
      const vault = (await fetchVault()).vault;
      await rotateCredential({
        ...args,
        credentialVersion: vault.credential_version,
        targetKdf: target,
      });
    } catch (e) {
      console.warn(
        "Vault protection upgrade did not finish; it will retry on the next unlock.",
        e,
      );
    } finally {
      args.vaultKeyRaw.fill(0);
    }
  };

  scheduleIdle(run);
}

/**
 * Runs `task` when the browser is idle so a KDF does not block the unlock's
 * first paint. Falls back to a short timeout where `requestIdleCallback` is
 * absent. There is no Worker yet; see plans/p0-kdf-profile.md §10.3.
 */
function scheduleIdle(task: () => Promise<void>): void {
  const run = () => {
    void task();
  };
  if (typeof requestIdleCallback === "function") {
    requestIdleCallback(run, { timeout: 3_000 });
  } else {
    setTimeout(run, 250);
  }
}

/**
 * Settings path: verify the master password by unwrapping the current envelope,
 * then rotate to this device's calibrated target. Returns `skipped` when the
 * vault is already at or above that target (the calibrated rung can be lower
 * than the vault's on a slower device; we never downgrade).
 */
export async function upgradeVaultKdfWithPassword(
  vaultId: string,
  password: string,
): Promise<"rotated" | "already" | "skipped"> {
  const [params, vaultData] = await Promise.all([
    fetchCryptoParams(vaultId),
    fetchVault(),
  ]);
  const vault = vaultData.vault;
  if (!vault.vault_key_wrap || !vault.vault_key_wrap_iv) {
    throw new Error("Vault key material unavailable for upgrade.");
  }

  const current = await derivePasswordKeys(password, params.salt, params.kdf);
  let raw: Uint8Array;
  try {
    raw = await unwrapKeyBytes(
      vault.vault_key_wrap,
      vault.vault_key_wrap_iv,
      current.wrappingKey,
    );
  } catch {
    // A wrong password fails the GCM tag, exactly like an unlock.
    throw new Error("Incorrect password.");
  }

  try {
    const target = await ensureKdfTarget();
    if (kdfRank(target) <= kdfRank(params.kdf)) return "skipped";
    return await rotateCredential({
      vaultId,
      password,
      currentKdf: params.kdf,
      currentVerifier: current.vaultVerifier,
      vaultKeyRaw: raw,
      credentialVersion: vault.credential_version,
      targetKdf: target,
    });
  } finally {
    raw.fill(0);
  }
}
