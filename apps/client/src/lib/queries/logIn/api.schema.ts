import type { KdfParams } from "@voult/vault-core";

export type LoginRequest = {
    vault_id: string;
    vault_verifier: string;
}

export type LoginResponse = {
    vault_id: string;
    salt: string;
    /** Password KDF profile; paired with `salt` to derive the wrapping key. */
    kdf: KdfParams;
    crypto_version: number;
    /** CAS counter for the password credential; needed by a profile rotation. */
    credential_version: number;
    vault_key_wrap: string | null;
    vault_key_wrap_iv: string | null;
}
