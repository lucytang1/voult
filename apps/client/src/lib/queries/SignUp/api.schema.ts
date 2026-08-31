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
