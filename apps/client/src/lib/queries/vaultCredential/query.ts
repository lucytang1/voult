import { http } from "../http";
import type {
  RotateCredentialRequest,
  RotateCredentialResponse,
} from "./api.schema";

/**
 * Rotates the password credential. The server never sees the password or the
 * vault key: the body is a fresh salt, a published KDF profile, the derived
 * verifier, and a fresh AES-GCM wrap of the same raw vault key.
 */
export async function rotateVaultCredential(
  payload: RotateCredentialRequest,
): Promise<RotateCredentialResponse> {
  const response = await http.post<RotateCredentialResponse>(
    "/vault/credential",
    payload,
  );
  return response.data;
}
