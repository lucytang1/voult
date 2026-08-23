export type LoginRequest = {
    email: string;
    user_key: string;
}

export type LoginResponse = {
    user: User;
    salt: string;
    iterations: number;
    crypto_version: number;
}

type User = {
    id: string;
    email: string;
}
