import { http } from "../http";
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
 * Plain async transport functions for the recovery endpoints, so the flows in
 * `lib/auth/flows` can call them outside React (the /recover screen drives the
 * flow imperatively, not through a query hook).
 */

export async function postRecoveryChallenge(
    payload: RecoveryChallengeRequest,
): Promise<RecoveryChallengeResponse> {
    const response = await http.post<RecoveryChallengeResponse>(
        "/recovery/challenge",
        payload,
    );
    return response.data;
}

export async function postRecoveryUnlock(
    payload: RecoveryUnlockRequest,
): Promise<RecoveryUnlockResponse> {
    const response = await http.post<RecoveryUnlockResponse>("/recovery/unlock", payload);
    return response.data;
}

export async function postRecoveryRewrap(
    payload: RecoveryRewrapRequest,
): Promise<RecoveryRewrapResponse> {
    const response = await http.post<RecoveryRewrapResponse>("/recovery/rewrap", payload);
    return response.data;
}

export async function postRecoveryRegenerate(
    payload: RecoveryRegenerateRequest,
): Promise<RecoveryRegenerateResponse> {
    const response = await http.post<RecoveryRegenerateResponse>(
        "/recovery/regenerate",
        payload,
    );
    return response.data;
}