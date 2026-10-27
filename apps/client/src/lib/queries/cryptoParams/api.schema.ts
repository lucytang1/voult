export type SaltRequest = {
    vault_id: string;
}

export type SaltResponse = {
    salt: string;
    iterations: number;
    // Case 3: the client needs recovery_salt to derive K_rec before it can
    // unwrap the recovery envelope, and has_recovery to tell whether this vault
    // is recoverable at all. Served pre-auth because recovery has no session.
    // Optional here only because this type mirrors an older server; every server
    // that has the recovery migration always sends both.
    recovery_salt?: string | null;
    has_recovery?: boolean;
}