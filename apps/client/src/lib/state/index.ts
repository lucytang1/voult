import { create } from "zustand";
import { AppState, DecryptedVault, VaultItem } from "./type";
import { UpdateVaultItem, CreateVaultItem, DeleteVaultItem } from "../sync/type";

const useAppStore = create<AppState>()((set) => ({
  encryptionKey: null,
  authKey: null,
  decryptedVault: null,
  vaultVersion: null,
  isSyncing: false,
}));

const updateEncryptionKey = (encryptionKey: CryptoKey) =>
  useAppStore.setState({ encryptionKey });
const updateAuthKey = (authKey: CryptoKey) => useAppStore.setState({ authKey });
const updateVaultVersion = (vaultVersion: number) =>
  useAppStore.setState({ vaultVersion });
const setSyncStatus = (isSyncing: boolean) =>
  useAppStore.setState({ isSyncing });

const updateDecryptedVault = (decryptedVault: DecryptedVault) =>
  useAppStore.setState({ decryptedVault });

const addVaultItem = (item: CreateVaultItem) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      items: state.decryptedVault
        ? [...state.decryptedVault.items, item]
        : [item],
    },
  }));

const updateVaultItem = (
  updateditem: UpdateVaultItem,
) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      items:
        state.decryptedVault?.items.map((item) =>
          item.id === updateditem.id ? { ...item, ...updateditem.fields} : item,
        ) ?? [],
    },
  }));

const deleteVaultItem = (deleteitem: DeleteVaultItem) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      items:
        state.decryptedVault?.items.filter(
          (item) => !(item.id === deleteitem.id),
        ) ?? [],
    },
  }));

export {
  useAppStore,
  updateEncryptionKey,
  updateDecryptedVault,
  updateAuthKey,
  updateVaultVersion,
  setSyncStatus,
  addVaultItem,
  updateVaultItem,
  deleteVaultItem,
};
