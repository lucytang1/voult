export type RegisterRequest = {
    email: string;
    user_key: string;
    salt: string;
    iterations: number;
    vaultiv: string;
    vault: string;
    crypto_version: number;
    vault_key_wrap: string;
    vault_key_wrap_iv: string;
}

export type RegisterResponse = {
    user: User;
    vault: string;
    salt: string;
    iterations: number;
    vaultiv: string;
}

type User = {
    id: string;
    email: string;
}
