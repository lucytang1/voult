export type RegisterRequest = {
    email: string;
    user_key: string;
    salt: string;
    iterations: number;
    vaultiv: string;
    vault: string;
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