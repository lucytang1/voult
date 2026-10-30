import type { KdfParams } from "@voult/vault-core";

export type SaltRequest = {
    vault_id: string;
}

export type SaltResponse = {
    salt: string;
    /**
     * Password KDF profile. Validated against the client's own ladder before
     * any derivation, so a server cannot make the client allocate an absurd
     * amount of memory.
     */
    kdf: KdfParams;
    // Case 3: the client needs recovery_salt to derive K_rec before it can
    // unwrap the recovery envelope, and has_recovery to tell whether this vault
    // is recoverable at all. Served pre-auth because recovery has no session.
    recovery_salt?: string | null;
    has_recovery?: boolean;
}
