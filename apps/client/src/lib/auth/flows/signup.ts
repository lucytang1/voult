import {
    PBKDF2_ITERATIONS,
    CRYPTO_VERSION,
    newSaltB64,
    generateVaultKeyRaw,
    importVaultKey,
    encrypt,
    wrapKeyBytes,
    b64,
    uuid,
} from "../../crypto/index.web";
import { derivePasswordKeys, generateRecoveryMaterial, parseVaultJson } from "../utils";
import type { PendingVaultRegistration } from "../../vault/registration";
import { normalizeVaultName } from "../../vault/name";

/**
 * Vault creation, up to but NOT including the network.
 *
 * Step 1 of 2, and it deliberately stops short of talking to the server:
 *   1. `prepareSignupFlow` — everything derivable from the master password is
 *      derived here: vault id, vault key, ciphertext, password envelope,
 *      recovery secret, recovery envelope. Purely local. The caller shows the
 *      recovery file and waits.
 *   2. `commitVaultRegistration` (`lib/vault/registration.ts`) — the single
 *      `POST /register`, run only once the user has that file.
 *
 * The split is the whole point. Registration used to happen first and the file
 * second, which meant a reload in between left a working vault whose recovery
 * path could never be repaired — see the invariant documented on
 * `PendingVaultRegistration`.
 *
 * Both envelopes wrap the SAME raw vault key:
 *   - the password envelope, under the PBKDF2-derived wrapping key;
 *   - the recovery envelope, under K_rec (Rule R1: the recovery envelope wraps
 *     `vaultKeyRaw` directly, never a password-derived key, so rotating the
 *     password later cannot destroy the recovery path).
 */
export async function prepareSignupFlow(
    password: string,
    requestedName: string,
): Promise<PendingVaultRegistration> {
    const name = normalizeVaultName(requestedName);
    if (!name) {
        throw new Error("Vault names must be between 1 and 48 characters.");
    }
    // The name is part of the encrypted document from the very first write: it
    // is the user's label for the vault, and the server must never see it.
    //
    // A new vault is ALWAYS empty. There is no seed list and no call-site
    // freedom to add one: the document is written here, at creation, and every
    // entry the user ever has is one they added themselves. (This used to be a
    // `starter: { name, items }` argument, which let a screen ship three
    // `test@example.com` / `password` rows into every real user's vault.)
    const vaultJson = JSON.stringify({ name, items: [] });
    // The vault ID is generated client-side and never derived from any identity.
    const vaultId = uuid();
    const salt = newSaltB64();
    const { vaultVerifier, wrappingKey } = await derivePasswordKeys(password, salt, PBKDF2_ITERATIONS);

    const vaultKeyRaw = generateVaultKeyRaw();
    const vaultKey = await importVaultKey(vaultKeyRaw);

    const encryptedVault = await encrypt(vaultJson, vaultKey);

    const { cipher: wrappedCipher, iv: wrappedIv } = await wrapKeyBytes(
        vaultKeyRaw,
        wrappingKey,
    );

    // Recovery material. The secret is 160 bits of CSPRNG — deliberately not a
    // user-chosen passphrase, which would inherit the password KDF's weakness.
    const recovery = await generateRecoveryMaterial(vaultKeyRaw, vaultId);

    console.info("Vault prepared locally; nothing has been sent to the server yet");

    return {
        vaultId,
        cryptoVersion: CRYPTO_VERSION,
        version: 1,
        request: {
            vault_id: vaultId,
            vault_verifier: vaultVerifier,
            salt,
            iterations: PBKDF2_ITERATIONS,
            vaultiv: b64(encryptedVault.iv),
            vault: b64(encryptedVault.cipher),
            crypto_version: CRYPTO_VERSION,
            vault_key_wrap: b64(wrappedCipher),
            vault_key_wrap_iv: b64(wrappedIv),
            recovery_verifier: b64(recovery.recoveryVerifier),
            recovery_salt: recovery.recoverySalt,
            recovery_wrap: recovery.recoveryWrap,
            recovery_wrap_iv: recovery.recoveryWrapIv,
        },
        vaultKey,
        vaultKeyRaw,
        // Stamped with the id it was created under, so the decrypted vault
        // carries the same identity the session will.
        decryptedVault: parseVaultJson(vaultJson, vaultId),
        recoveryKey: recovery.recoveryKey,
    };
}

export async function createAccountFlow(...a: any) {
    throw new Error("deprecated");
}