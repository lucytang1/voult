export type LoginRequest = {
    email: string;
    user_key: string;
}

export type LoginResponse = {
    user: User;
}

type User = {
    id: string;
    email: string;
}