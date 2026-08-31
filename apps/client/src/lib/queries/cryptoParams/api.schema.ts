export type SaltRequest = {
    vault_id: string;
}

export type SaltResponse = {
    salt: string;
    iterations: number;
}