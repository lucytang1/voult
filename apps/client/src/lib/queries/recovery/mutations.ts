import { useMutation } from "@tanstack/react-query";
import {
    postRecoveryChallenge,
    postRecoveryRegenerate,
    postRecoveryRewrap,
    postRecoveryUnlock,
} from "./query";
import type {
    RecoveryChallengeRequest,
    RecoveryChallengeResponse,
    RecoveryRegenerateRequest,
    RecoveryRegenerateResponse,
    RecoveryRewrapRequest,
    RecoveryRewrapResponse,
    RecoveryUnlockRequest,
    RecoveryUnlockResponse,
} from "./api.schema";

/**
 * Mutation hooks for the recovery endpoints.
 *
 * These exist for the Settings rotation flow, which is a button rather than a
 * multi-step journey. The /recover flow deliberately does NOT use them — it must
 * run each step in order and abort cleanly between them, which an imperative
 * flow function expresses far better than three independent mutations.
 *
 * `gcTime: 0` matches the other mutation hooks: nothing that can carry recovery
 * state should outlive the component that started it.
 */

export const useRecoveryChallengeMutation = () =>
    useMutation<RecoveryChallengeResponse, Error, RecoveryChallengeRequest>({
        mutationFn: postRecoveryChallenge,
        gcTime: 0,
    });

export const useRecoveryUnlockMutation = () =>
    useMutation<RecoveryUnlockResponse, Error, RecoveryUnlockRequest>({
        mutationFn: postRecoveryUnlock,
        gcTime: 0,
    });

export const useRecoveryRewrapMutation = () =>
    useMutation<RecoveryRewrapResponse, Error, RecoveryRewrapRequest>({
        mutationFn: postRecoveryRewrap,
        gcTime: 0,
    });

/** Rotates the recovery key of the currently selected vault. */
export const useRecoveryRegenerateMutation = () =>
    useMutation<RecoveryRegenerateResponse, Error, RecoveryRegenerateRequest>({
        mutationFn: postRecoveryRegenerate,
        gcTime: 0,
    });