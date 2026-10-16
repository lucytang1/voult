import {
    CRYPTO_VERSION,
    PBKDF2_ITERATIONS,
    b64,
    decrypt,
    deriveRecoveryWrapKey,
    computeRecoveryVerifier,
    computeRecoveryProof,
    importVaultKey,
    newSaltB64,
    parseRecoveryKey,
    recoveryAad,
    unwrapKeyBytes,
    wrapKeyBytes,
    RecoveryPdfError,
} from "../../crypto/index.web";
import {
    postRecoveryChallenge,
    postRecoveryRewrap,
    postRecoveryUnlock,
} from "../../queries/recovery/query";
import { fetchCryptoParams } from "../../queries/cryptoParams/query";
import { fetchVault } from "../../queries/vault/query";
import { derivePasswordKeys, parseVaultJson, persistDeviceSecrets } from "../utils";
import type { UnlockedSession } from "../utils";

/**
 * Vault recovery, case 3: the user holds a recovery file, has no device key
 * (cleared site data or a new machine), and does not remember the master
 * password.
 *
 * Deliberately split into two steps across two screens, so an unusable
 * recovery file is discovered BEFORE the user is asked to invent a new
 * password:
 *
 *   1. `verifyRecoveryKey` — prove possession of the recovery secret and
 *      recover `vaultKeyRaw`. No session, no vault row touched, nothing
 *      irreversible. Costs three local KDF/HMAC operations and two round-trips.
 *   2. `completeRecovery`   — derive the new password credential, verify it
 *      LOCALLY, then perform the single irreversible server write and open the
 *      vault.
 *
 * The split also removes the stale-challenge problem. Each step mints its own
 * challenge, so the 10-minute TTL only has to cover the moments inside a step —
 * not however long the user takes to choose a password.
 *
 * Neither step knows or cares that the secret arrived inside a PDF: the screen
 * parses the file and passes a plain recovery key down. Keeping the artifact
 * out of the flow is what lets the same code serve recovery, rotation, and
 * anything else that holds a key.
 */

export interface RecoveredVault extends UnlockedSession {
    /** Raw vault key bytes, so the caller can enrol this device. */
    vaultKeyRaw: Uint8Array;
}

/**
 * Everything step 2 needs, held in module memory between the two screens.
 *
 * Deliberately **not** in the Zustand store and **not** persisted: this is the
 * vault key in the clear, and it should live for exactly as long as the user is
 * mid-recovery. It is wiped by `completeRecovery` (success or terminal failure)
 * and by `abandonPendingRecovery` (going back).
 *
 * The raw recovery secret is **not** retained — only `recoveryVerifier`, which is
 * sufficient to mint a fresh proof and is not a stronger secret than the copy the
 * server already holds. So the strongest thing sitting in memory between screens
 * is the vault key, which step 2 needs to wrap the new password envelope.
 */
interface PendingRecovery {
    vaultId: string;
    /** HMAC-SHA256(K_rec, "recovery-verify-v1"). Enough to make proofs. */
    verifier: Uint8Array;
    /** The recovered vault key — wrapped under the new password in step 2. */
    vaultKeyRaw: Uint8Array;
    /**
     * The vault's `credential_version` at step 1, which step 2's rewrap must
     * present for the CAS to succeed. It is NOT safe to assume 0: a vault that
     * has already been recovered once would then lose the compare-and-swap with
     * 409 CREDENTIAL_STALE and become unrecoverable. Carried across the screen
     * boundary for exactly that reason.
     */
    credentialVersion: number;
}

let pending: PendingRecovery | null = null;

/** True when step 1 has succeeded and step 2 can be opened. */
export function hasPendingRecovery(): boolean {
    return pending !== null;
}

/** The vault id currently being recovered, for the step-2 header. */
export function pendingRecoveryVaultId(): string | null {
    return pending?.vaultId ?? null;
}

/**
 * Wipes the in-memory recovery state. Call on success, on terminal failure, and
 * when the user backs out of step 2.
 */
export function abandonPendingRecovery(): void {
    if (!pending) return;
    // Best-effort zeroization. JavaScript cannot guarantee this (the engine may
    // have copied the bytes), but it removes the obvious long-lived reference.
    pending.verifier.fill(0);
    pending.vaultKeyRaw.fill(0);
    pending = null;
}

/**
 * Step 1 — verify the recovery key and recover the vault key.
 *
 * Nothing is written on the server and no session is established. In
 * particular the document is NOT decrypted here: `get_vault` requires a session,
 * and nothing has established one yet. Step 2 proves the recovered key actually
 * opens the document, after the rewrap has set a session.
 *
 * Throws `INVALID_RECOVERY_KEY` for a malformed key and `RECOVERY_NOT_ENABLED`
 * for a vault with no recovery — both conditions the user can actually act on,
 * and deliberately distinct from a rejected proof.
 */
export async function verifyRecoveryKey(args: {
    vaultId: string;
    recoveryKey: string;
}): Promise<{ vaultId: string }> {
    const { vaultId, recoveryKey } = args;

    // Pre-auth params. `recovery_salt` is the only thing needed before the
    // secret can be turned into K_rec, and `has_recovery` says whether this
    // vault is recoverable at all.
    const params = await fetchCryptoParams(vaultId);
    if (!params.has_recovery || !params.recovery_salt) {
        throw new Error("RECOVERY_NOT_ENABLED");
    }

    // Strict: throws on a bad length or an out-of-alphabet character, with a
    // message the UI can distinguish from a server rejection.
    let secretBytes: Uint8Array;
    try {
        secretBytes = parseRecoveryKey(recoveryKey);
    } catch {
        throw new Error("INVALID_RECOVERY_KEY");
    }

    // No PBKDF2 on this path by design: the secret already carries 160 bits.
    const K = await deriveRecoveryWrapKey(secretBytes, params.recovery_salt);

    // A fresh server nonce — this is what makes the proof non-replayable.
    const { selector, challenge } = await postRecoveryChallenge({ vault_id: vaultId });

    const verifier = await computeRecoveryVerifier(secretBytes, params.recovery_salt);
    const proof = await computeRecoveryProof(verifier, vaultId, challenge);
    secretBytes.fill(0);

    const released = await postRecoveryUnlock({
        vault_id: vaultId,
        selector,
        proof: b64(proof),
    });

    // AAD binds this envelope to this vault, so a `recovery_wrap` row lifted onto
    // another vault fails here rather than decrypting cleanly.
    let vaultKeyRaw: Uint8Array;
    try {
        vaultKeyRaw = await unwrapKeyBytes(
            released.recovery_wrap,
            released.recovery_wrap_iv,
            K,
            recoveryAad(vaultId),
        );
    } catch {
        throw new Error("RECOVERY_FAILED");
    }

    // Replace any earlier attempt rather than accumulating.
    abandonPendingRecovery();
    pending = { vaultId, verifier, vaultKeyRaw, credentialVersion: released.credential_version };
    return { vaultId };
}

/**
 * Step 2 — set a new master password, then open the vault.
 *
 * Throws `RECOVERY_EXPIRED` if step 1 was never completed (direct navigation,
 * or a reload), so the screen can send the user back rather than failing
 * obscurely.
 */
export async function completeRecovery(args: { newPassword: string }): Promise<RecoveredVault> {
    const state = pending;
    if (!state) throw new Error("RECOVERY_EXPIRED");
    const { vaultId, verifier, vaultKeyRaw, credentialVersion } = state;

    try {
        // LOCAL VERIFICATION, before the single irreversible server write.
        //
        // Derive the brand-new password credential, then unwrap with it and
        // require byte-equality with the key we already hold. This catches a
        // typo in the new password, a bad salt, or a derivation bug — all
        // locally, while failing is still free. Sending an unverified
        // credential to the server would be the one unrecoverable mistake this
        // flow can make.
        const newSalt = newSaltB64();
        const { wrappingKey, vaultVerifier } = await derivePasswordKeys(
            args.newPassword,
            newSalt,
            PBKDF2_ITERATIONS,
        );
        const newEnvelope = await wrapKeyBytes(vaultKeyRaw, wrappingKey);
        let roundTrip: Uint8Array;
        try {
            roundTrip = await unwrapKeyBytes(b64(newEnvelope.cipher), b64(newEnvelope.iv), wrappingKey);
        } catch {
            throw new Error("RECOVERY_FAILED");
        }
        if (!bytesEqual(roundTrip, vaultKeyRaw)) {
            throw new Error("RECOVERY_FAILED");
        }

        // A FRESH challenge, minted here rather than carried over from step 1.
        // Re-minting costs one round-trip and buys immunity to the 10-minute TTL
        // expiring while the user chooses a password.
        const { selector, challenge } = await postRecoveryChallenge({ vault_id: vaultId });
        const proof = await computeRecoveryProof(verifier, vaultId, challenge);

        // The one irreversible write. Rotates the password credential and sets
        // the session cookie. Recovery material is untouched, so the same
        // recovery key still works afterwards (Rule R1).
        const rewrapped = await postRecoveryRewrap({
            vault_id: vaultId,
            selector,
            proof: b64(proof),
            credential_version: credentialVersion,
            new_salt: newSalt,
            new_iterations: PBKDF2_ITERATIONS,
            new_vault_verifier: vaultVerifier,
            new_vault_key_wrap: b64(newEnvelope.cipher),
            new_vault_key_wrap_iv: b64(newEnvelope.iv),
        });

        // Prove the recovered key actually opens the document before letting the
        // caller commit to an unlocked state.
        const vaultData = await fetchVault();
        const vault = vaultData.vault;
        const plain = await decrypt(vault.vault, vault.vaultiv, await importVaultKey(vaultKeyRaw));

        // This device had no device key — that is the whole premise of case 3.
        // Create one now so the next unlock is a local unwrap.
        await persistDeviceSecrets(vaultKeyRaw, vaultId);

        console.info("Vault recovered; device key enrolled");

        return {
            session: {
                vaultId,
                cryptoVersion: vault.crypto_version ?? rewrapped.crypto_version ?? CRYPTO_VERSION,
            },
            vaultKey: await importVaultKey(vaultKeyRaw),
            vaultKeyRaw,
            decryptedVault: parseVaultJson(plain, vaultId),
            version: vault.version,
            lockEpoch: rewrapped.lock_epoch,
        };
    } finally {
        // Whether we succeeded or hit a terminal failure, the pending state has
        // served its purpose — including on a validation error, which the user
        // should be able to fix by simply trying the password again.
        abandonPendingRecovery();
    }
}

/** Length-independent byte equality. Not a secret comparison — both operands
 *  are key material this process just produced. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
    return diff === 0;
}

/**
 * Turns a recovery failure into something the screen can render honestly.
 *
 * The server answers a wrong key, an expired challenge, and an unknown vault
 * identically, so those all collapse to one message. Deliberately NOT folded in
 * are the conditions the user can act on themselves: an unusable recovery file,
 * a vault with no recovery configured, and a step-1 state that no longer
 * exists.
 */
export function describeRecoveryError(e: unknown): string {
    const message = (e as Error)?.message;
    const code = (e as { response?: { data?: { code?: string } } })?.response?.data?.code;
    const status = (e as { response?: { status?: number } })?.response?.status;

    // File-level failures already carry copy written for this exact situation
    // ("That is not a PDF…", "a print-out may not carry it"), and inventing a
    // second, vaguer version of the same message here would only throw it away.
    if (e instanceof RecoveryPdfError) return e.message;

    switch (message) {
        case "INVALID_RECOVERY_KEY":
            return "That recovery key is not well-formed.";
        case "RECOVERY_NOT_ENABLED":
            return "This vault has no recovery key, or it is not on this server. Restore from a backup file instead.";
        case "RECOVERY_FILE_OTHER_VAULT":
            return "That recovery file is for a different vault. Each vault has its own file, with its vault id printed on it.";
        case "RECOVERY_EXPIRED":
            return "This recovery attempt is no longer active. Open your recovery file again.";
        case "RECOVERY_FAILED":
            return "Recovery failed. Check the recovery file.";
    }

    if (code === "CREDENTIAL_STALE") {
        return "This vault was already recovered in another tab. Unlock it normally.";
    }
    if (code === "RECOVERY_STALE") {
        return "The recovery key was already rotated. Reload and try again.";
    }
    if (status === 404) {
        return "This vault is not on this server. Restore from a backup file instead.";
    }
    if (status === undefined) {
        return "Cannot reach the server. Check your connection and try again.";
    }
    // The server's own uniform message: "Recovery failed. Check the recovery key."
    return (
        (e as { response?: { data?: { error_msg?: string } } })?.response?.data?.error_msg ||
        "Recovery failed. Check the recovery key."
    );
}