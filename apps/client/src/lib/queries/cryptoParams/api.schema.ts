export type SaltRequest = {
    email: string;
}

export type SaltResponse = {
    salt: string;
    iterations: number;
}