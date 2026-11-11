import type { KdfParams } from "@voult/vault-core";

/**
 * `POST /api/vault/credential` — atomically replace the password credential
 * after a purely local rewrap.
 *
 * `current_vault_verifier` is a reauthentication proof (the server compares it
 * to the stored verifier before writing), not an identity. `credential_version`
 * is the CAS guard: the write only lands if nobody else rotated in between.
 */
export type RotateCredentialRequest = {
  current_vault_verifier: string;
  credential_version: number;
  new_salt: string;
  new_kdf: KdfParams;
  new_vault_verifier: string;
  new_vault_key_wrap: string;
  new_vault_key_wrap_iv: string;
};

export type RotateCredentialResponse = {
  vault_id: string;
  credential_version: number;
  kdf: KdfParams;
  lock_epoch: number;
};
