import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  disconnectGoogle,
  getGoogleBinding,
  getGoogleStatus,
  listGoogleVaults,
  listGoogleVaultsPending,
  linkPendingGoogleToken,
  mirrorGoogleVault,
  persistGoogleBinding,
  startGoogleAuth,
  type VaultDescriptor,
} from "./api";

export const googleKeys = {
  status: (vaultId: string) => ["google", "status", vaultId] as const,
  vaults: (vaultId: string) => ["google", "vaults", vaultId] as const,
  pendingVaults: (state: string) => ["google", "pending-vaults", state] as const,
  binding: (vaultId: string) => ["google", "binding", vaultId] as const,
};

export function useGoogleStatus(vaultId = "current", enabled = true) {
  return useQuery({
    queryKey: googleKeys.status(vaultId),
    queryFn: getGoogleStatus,
    enabled,
    staleTime: 30_000,
    retry: false,
  });
}

export function useGoogleVaults(vaultId: string, enabled: boolean) {
  return useQuery<VaultDescriptor[]>({
    queryKey: googleKeys.vaults(vaultId),
    queryFn: listGoogleVaults,
    enabled,
    staleTime: 30_000,
  });
}

export function usePendingGoogleVaults(state?: string) {
  return useQuery({
    queryKey: googleKeys.pendingVaults(state ?? ""),
    queryFn: () => listGoogleVaultsPending(state!),
    enabled: !!state,
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });
}

export function useGoogleBinding(vaultId?: string, enabled = !!vaultId) {
  return useQuery({
    queryKey: googleKeys.binding(vaultId ?? ""),
    queryFn: () => getGoogleBinding(vaultId!),
    enabled: !!vaultId && enabled,
    // Backup state changes out of band (the server mirrors after each vault
    // write), so a cached value can be arbitrarily stale. Refetch on focus and
    // keep a short window otherwise.
    staleTime: 5_000,
    refetchOnWindowFocus: true,
    retry: false,
  });
}

/**
 * Explicit "Back up now". The automatic mirror is detached server-side, so this
 * is how the UI learns a real outcome; it refreshes the binding on success so
 * the displayed watermark matches what Drive actually holds.
 */
export function useMirrorGoogleVault(vaultId?: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: mirrorGoogleVault,
    gcTime: 0,
    onSuccess: async (data) => {
      // The server returns the binding it just wrote; use it directly rather
      // than refetching, so the UI reflects the outcome immediately.
      if (data.binding && vaultId) {
        queryClient.setQueryData(googleKeys.binding(vaultId), data.binding);
      } else if (vaultId) {
        await queryClient.invalidateQueries({ queryKey: googleKeys.binding(vaultId) });
      }
    },
  });
}

export function useStartGoogleAuth() {
  return useMutation({ mutationFn: startGoogleAuth, gcTime: 0 });
}

export function useDisconnectGoogle() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: disconnectGoogle,
    gcTime: 0,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["google", "status"] }),
        queryClient.invalidateQueries({ queryKey: ["google", "binding"] }),
        queryClient.invalidateQueries({ queryKey: ["google", "vaults"] }),
      ]);
    },
  });
}

export function useLinkPendingGoogleToken() {
  return useMutation({ mutationFn: linkPendingGoogleToken, gcTime: 0 });
}

export function usePersistGoogleBinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: persistGoogleBinding,
    gcTime: 0,
    onSuccess: async (_result, input) => {
      await queryClient.invalidateQueries({ queryKey: googleKeys.binding(input.vault_id) });
    },
  });
}
