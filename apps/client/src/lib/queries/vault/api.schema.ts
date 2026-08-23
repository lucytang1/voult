export type VaultResponse = {
    vault: {
        vault: string;
        vaultiv: string;
        iterations: number;
        version: number;
        crypto_version: number;
        vault_key_wrap: string | null;
        vault_key_wrap_iv: string | null;
    }
}

export type UpdateVaultRequest = {
  vault: string;
  vaultiv: string;
  version: number;
  crypto_version?: number;
  vault_key_wrap?: string;
  vault_key_wrap_iv?: string;
};

export type UpdateVaultResponse = {
  vault: string;
  vaultiv: string;
  iterations: number;
  version: number;
  crypto_version: number;
  vault_key_wrap: string | null;
  vault_key_wrap_iv: string | null;
};
