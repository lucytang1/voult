import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  disconnectCloud,
  getCloudBinding,
  getCloudStatus,
  listCloudVaults,
  listCloudVaultsPending,
  listCloudProviders,
  listCloudCredentials,
  linkPendingCloudToken,
  mirrorCloudVault,
  persistCloudBinding,
  startCloudAuth,
  type VaultDescriptor,
} from "./api";

export const cloudKeys = {
  providers: () => ["cloud", "providers"] as const,
  status: (vaultId: string) => ["cloud", "status", vaultId] as const,
  vaults: (vaultId: string) => ["cloud", "vaults", vaultId] as const,
  pendingVaults: (state: string) => ["cloud", "pending-vaults", state] as const,
  binding: (vaultId: string) => ["cloud", "binding", vaultId] as const,
};

export function useCloudProviders() {
  return useQuery({ queryKey: cloudKeys.providers(), queryFn: listCloudProviders, staleTime: 60_000, retry: false });
}

export function useCloudCredentials(enabled = true) {
  return useQuery({ queryKey: ["cloud", "credentials"] as const, queryFn: listCloudCredentials, enabled, staleTime: 0, retry: false });
}

export function useCloudStatus(vaultId = "current", enabled = true) {
  return useQuery({
    queryKey: cloudKeys.status(vaultId),
    queryFn: getCloudStatus,
    enabled,
    staleTime: 30_000,
    retry: false,
  });
}

export function useCloudVaults(vaultId: string, enabled: boolean) {
  return useQuery<VaultDescriptor[]>({
    queryKey: cloudKeys.vaults(vaultId),
    queryFn: listCloudVaults,
    enabled,
    staleTime: 30_000,
  });
}

export function usePendingCloudVaults(state?: string) {
  return useQuery({
    queryKey: cloudKeys.pendingVaults(state ?? ""),
    queryFn: () => listCloudVaultsPending(state!),
    enabled: !!state,
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });
}

export function useCloudBinding(vaultId?: string, enabled = !!vaultId) {
  return useQuery({
    queryKey: cloudKeys.binding(vaultId ?? ""),
    queryFn: () => getCloudBinding(vaultId!),
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
export function useMirrorCloudVault(vaultId?: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: mirrorCloudVault,
    gcTime: 0,
    onSuccess: async (data) => {
      // The server returns the binding it just wrote; use it directly rather
      // than refetching, so the UI reflects the outcome immediately.
      if (data.binding && vaultId) {
        queryClient.setQueryData(cloudKeys.binding(vaultId), data.binding);
      } else if (vaultId) {
        await queryClient.invalidateQueries({ queryKey: cloudKeys.binding(vaultId) });
      }
    },
  });
}

export function useStartCloudAuth() {
  return useMutation({ mutationFn: startCloudAuth, gcTime: 0 });
}

export function useDisconnectCloud() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: disconnectCloud,
    gcTime: 0,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["cloud", "status"] }),
        queryClient.invalidateQueries({ queryKey: ["cloud", "binding"] }),
        queryClient.invalidateQueries({ queryKey: ["cloud", "vaults"] }),
        queryClient.invalidateQueries({ queryKey: ["cloud", "credentials"] }),
      ]);
    },
  });
}

export function useLinkPendingCloudToken() {
  return useMutation({ mutationFn: linkPendingCloudToken, gcTime: 0 });
}

export function usePersistCloudBinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: persistCloudBinding,
    gcTime: 0,
    onSuccess: async (_result, input) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: cloudKeys.binding(input.vault_id) }),
        queryClient.invalidateQueries({ queryKey: cloudKeys.status(input.vault_id) }),
        queryClient.invalidateQueries({ queryKey: ["cloud", "credentials"] }),
      ]);
    },
  });
}
