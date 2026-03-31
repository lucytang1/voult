import { create } from "zustand";
import { AppState, DecryptedVault, VaultItem } from "./type";

const useAppStore = create<AppState>()((set) => ({
  encryptionKey: null,
  authKey: null,
  decryptedVault: null,
  vaultVersion: null,
}));

const updateEncryptionKey = (encryptionKey: CryptoKey) =>
  useAppStore.setState({ encryptionKey });
const updateAuthKey = (authKey: CryptoKey) => useAppStore.setState({ authKey });
const updateVaultVersion = (vaultVersion: number) =>
  useAppStore.setState({ vaultVersion });

const updateDecryptedVault = (decryptedVault: DecryptedVault) =>
  useAppStore.setState({ decryptedVault });

const addVaultItem = (item: VaultItem) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      items: state.decryptedVault
        ? [...state.decryptedVault.items, item]
        : [item],
    },
  }));

const updateVaultItem = (
  site: string,
  username: string,
  updatedItem: VaultItem,
) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      items:
        state.decryptedVault?.items.map((item) =>
          item.site === site && item.username === username ? updatedItem : item,
        ) ?? [],
    },
  }));

const deleteVaultItem = (site: string, username: string) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      items:
        state.decryptedVault?.items.filter(
          (item) => !(item.site === site && item.username === username),
        ) ?? [],
    },
  }));

export {
  useAppStore,
  updateEncryptionKey,
  updateDecryptedVault,
  updateAuthKey,
  updateVaultVersion,
  addVaultItem,
  updateVaultItem,
  deleteVaultItem,
};
