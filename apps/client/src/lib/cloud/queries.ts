import { useMutation, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
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
  type CloudBinding,
  type VaultDescriptor,
} from "./api";
import { isBackupInFlight } from "./backup-view";

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
  return useQuery({
    queryKey: ["cloud", "credentials"] as const,
    queryFn: listCloudCredentials,
    enabled,
    staleTime: 0,
    // This is the account email shown on each provider row, so it should not
    // drift far behind a reconnect. It changes only on connect/disconnect.
    refetchInterval: enabled ? 30_000 : false,
    refetchIntervalInBackground: false,
    retry: false,
  });
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

export function useCloudBinding(
  vaultId?: string,
  options: { enabled?: boolean; fast?: boolean } = {},
) {
  const enabled = !!vaultId && (options.enabled ?? true);
  return useQuery<CloudBinding | null>({
    queryKey: cloudKeys.binding(vaultId ?? ""),
    queryFn: () => getCloudBinding(vaultId!),
    enabled,
    // Backup state changes out of band (the server mirrors after each vault
    // write), so a cached value can be arbitrarily stale — and a stale value is
    // exactly what makes the pane lie. Always revalidate on mount/focus.
    staleTime: 0,
    refetchOnWindowFocus: true,
    refetchOnMount: "always",
    // Adaptive polling. The mirror is detached server-side, so the only way to
    // learn it finished is to ask again: quickly while the copy is known to be
    // behind or in flight, lazily otherwise. `fast` pins it high while an action
    // this pane started (switch, manual backup) is running. Background tabs do
    // not poll; returning to the tab refetches immediately.
    refetchInterval: (query) => {
      if (options.fast) return 750;
      return isBackupInFlight(query.state.data) ? 1_000 : 15_000;
    },
    refetchIntervalInBackground: false,
    retry: false,
  });
}

/**
 * Write a binding into the cache only if it is not older than what is there.
 *
 * A mutation response can arrive after a provider switch (or a disconnect) has
 * already produced a newer binding; without this guard the late response would
 * resurrect the previous incarnation and the pane would describe a provider the
 * vault no longer backs up to.
 */
export function mergeCloudBinding(
  queryClient: QueryClient,
  vaultId: string,
  next: CloudBinding | null | undefined,
) {
  if (!next) return;
  queryClient.setQueryData<CloudBinding | null>(cloudKeys.binding(vaultId), (prev) =>
    !prev || next.binding_generation >= prev.binding_generation ? next : prev,
  );
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
      // than refetching, so the UI reflects the outcome immediately. The merge
      // drops it if a switch happened while the request was in flight.
      if (data.binding && vaultId) {
        mergeCloudBinding(queryClient, vaultId, data.binding);
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
