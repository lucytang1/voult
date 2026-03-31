export type VaultRequest = {
    email: string;
    user_key: string;
}

export type VaultResponse = {
    vault: {
        vault: string;
        vaultiv: string;
        iterations: number;
        version: number;
    }
}

export type UpdateVaultRequest = {
  email: string;
  user_key: string;
  vault: string;
  vaultiv: string;
  version: number;
};

export type UpdateVaultResponse = {
  vault: string;
  vaultiv: string;
  iteration: number;
  version: number;
};