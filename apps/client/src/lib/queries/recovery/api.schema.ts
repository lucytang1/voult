// Wire types for the vault-recovery endpoints (case 3).
//
// Note the asymmetry that is deliberate, not accidental: `/recovery/challenge`
// and `/recovery/unlock` are unauthenticated and take only a vault id, while
// `/recovery/rewrap` establishes the session and `/recovery/regenerate`
// requires one. See lib/auth/flows/recover.ts for the full flow.

export type RecoveryChallengeRequest = {
    vault_id: string;
}

export type RecoveryChallengeResponse = {
    /** Random public handle for the challenge row. Not a credential. */
    selector: string;
    /** CSPRNG(32), base64. Returned once; never re-issuable for this row. */
    challenge: string;
    expires_at: string;
}

export type RecoveryUnlockRequest = {
    vault_id: string;
    selector: string;
    /** HMAC bound to this vault id and this challenge; not replayable. */
    proof: string;
}

export type RecoveryUnlockResponse = {
    recovery_wrap: string;
    recovery_wrap_iv: string;
    credential_version: number;
}

export type RecoveryRewrapRequest = {
    vault_id: string;
    selector: string;
    proof: string;
    credential_version: number;
    new_salt: string;
    new_iterations: number;
    new_vault_verifier: string;
    new_vault_key_wrap: string;
    new_vault_key_wrap_iv: string;
}

export type RecoveryRewrapResponse = {
    vault_id: string;
    crypto_version: number;
    lock_epoch: number;
}

export type RecoveryRegenerateRequest = {
    vault_id: string;
    selector: string;
    /** Proof made with the CURRENT recovery key — the one being replaced. */
    proof: string;
    new_recovery_verifier: string;
    new_recovery_salt: string;
    new_recovery_wrap: string;
    new_recovery_wrap_iv: string;
}

export type RecoveryRegenerateResponse = {
    rotated: boolean;
}