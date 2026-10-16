export type RegisterRequest = {
    vault_id: string;
    vault_verifier: string;
    salt: string;
    iterations: number;
    vaultiv: string;
    vault: string;
    crypto_version: number;
    vault_key_wrap: string;
    vault_key_wrap_iv: string;
    // Recovery (case 3). Required by the server: a vault without these can
    // never be recovered, so registration is refused. Both envelopes wrap the
    // SAME raw vault key — never a password-derived key.
    recovery_verifier: string;
    recovery_salt: string;
    recovery_wrap: string;
    recovery_wrap_iv: string;
}

export type RegisterResponse = {
    vault_id: string;
    vault: string;
    salt: string;
    iterations: number;
    vaultiv: string;
    vault_key_wrap: string | null;
    vault_key_wrap_iv: string | null;
}
