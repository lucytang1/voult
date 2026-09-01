export type LoginRequest = {
    vault_id: string;
    vault_verifier: string;
}

export type LoginResponse = {
    vault_id: string;
    salt: string;
    iterations: number;
    crypto_version: number;
    vault_key_wrap: string | null;
    vault_key_wrap_iv: string | null;
}
