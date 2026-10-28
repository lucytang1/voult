import { useEffect, useRef, useState } from "react";
import { Pressable, Text, View, ScrollView, Modal, ActivityIndicator } from "react-native";
import { TextField } from "@/src/lib/components/text-field";
import { useRouter, useLocalSearchParams } from "expo-router";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import {
  useAppStore,
  selectVaultSession,
  switchVaultOpen,
  captureSelectionEpoch,
  updateDecryptedVault,
  updateLockEpoch,
  updateVaultVersion,
} from "@/src/lib/state";
import { selectedVaultId } from "@/src/lib/state/vault-state";
import { useVaultList, VaultSummary } from "@/src/lib/queries/vaults/query";
import { openVaultFlow, requiresSwitchConfirmation } from "@/src/lib/vault/open";
import { useCloudStatus, useCloudVaults, useLinkPendingCloudToken, usePendingCloudVaults, usePersistCloudBinding } from "@/src/lib/cloud/queries";
import { GoogleDriveIcon } from "../../../assets/images/GoogleDriveIcon";
import type { VaultDescriptor } from "@/src/lib/cloud/api";
import { importVaultFromCloud } from "@/src/lib/vault/import";
import { displayVaultName, hasKnownVaultName } from "@/src/lib/vault/name";
import { fetchSession } from "@/src/lib/queries/session/query";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { upsertVaultId, upsertVaultVersion } from "@/src/lib/sqlite/web/services/client-state-service";
import { forgetVaultFavicons } from "@/src/lib/favicon";

/**
 * Vault Chooser (vault-centric).
 * Shown when no vault is currently open. Lists, in order:
 * - Google Drive vaults (auto-listed: the user arrives here via
 *   "Continue with Google Drive", so no intermediate sign-in button)
 * - Existing local vaults/bindings (from GET /vaults, which is session-scoped)
 *
 * Vault creation lives on the landing page ("/") only. The back arrow
 * returns to "/" (landing) — never to the OAuth screen.
 *
 * All identity is the vault id; no email/account is collected. Switching warns
 * before discarding the currently-open vault's in-memory state.
 */
export default function VaultChooser() {
  const session = useAppStore((s) => s.session);
  const router = useRouter();
  const queryClient = useQueryClient();

  const [switchTarget, setSwitchTarget] = useState<VaultSummary | null>(null);
  const [switchPassword, setSwitchPassword] = useState("");
  const [switching, setSwitching] = useState(false);
  const [switchError, setSwitchError] = useState<string | null>(null);

  // Google Drive state
  const [googleImportTarget, setGoogleImportTarget] = useState<VaultDescriptor | null>(null);
  const [googleImportPassword, setGoogleImportPassword] = useState("");
  const [googleImportError, setGoogleImportError] = useState<string | null>(null);
  const [googleImporting, setGoogleImporting] = useState(false);
  const [sessionRestoreError, setSessionRestoreError] = useState<string | null>(null);
  const handledConnectedCallback = useRef(false);
  const params = useLocalSearchParams<{ cloud_connected?: string; cloud_error?: string; cloud_error_detail?: string; cloud_state?: string; provider?: string }>();
  const pendingState = (params as any).cloud_state as string | undefined
    || (typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("cloud_state") || undefined : undefined);
  const isGoogleCallback = !!pendingState || !!params.cloud_connected || !!params.cloud_error;

  const vaultListQuery = useVaultList(!!session, session?.vaultId);
  const googleStatusQuery = useCloudStatus(session?.vaultId ?? "pending", !!session || isGoogleCallback);
  const pendingGoogleVaultsQuery = usePendingCloudVaults(pendingState);
  const googleVaultsQuery = useCloudVaults(
    session?.vaultId ?? "anonymous",
    !pendingState && !!googleStatusQuery.data?.connected,
  );
  const linkPendingMutation = useLinkPendingCloudToken();
  const persistBindingMutation = usePersistCloudBinding();
  const vaults = vaultListQuery.data ?? null;
  const loading = !!session && vaultListQuery.isPending;
  const error = sessionRestoreError ?? (vaultListQuery.error instanceof Error ? vaultListQuery.error.message : null);
  const googleStatus = googleStatusQuery.data ?? null;
  const googleConfigured = googleStatusQuery.isError
    ? (googleStatusQuery.error as any)?.response?.data?.code !== "GOOGLE_NOT_CONFIGURED"
    : googleStatusQuery.isSuccess ? true : null;
  const googleVaults = (pendingState ? pendingGoogleVaultsQuery.data : googleVaultsQuery.data) ?? null;
  const googleLoading = pendingState
    ? pendingGoogleVaultsQuery.isPending
    : googleVaultsQuery.isPending;
  const googleVaultsError = pendingState ? pendingGoogleVaultsQuery.error : googleVaultsQuery.error;
  const googleError = googleVaultsError instanceof Error ? googleVaultsError.message : null;

  // A session-bound OAuth was started by Settings or Create. Once consent has
  // stored the credential, finish the requested provider switch/enrollment
  // against this authenticated vault instead of leaving the user at a chooser
  // that still reflects the previous binding.
  useEffect(() => {
    if (!session?.vaultId || !params.cloud_connected || !params.provider || pendingState || handledConnectedCallback.current) return;
    handledConnectedCallback.current = true;
    persistBindingMutation.mutateAsync({
      vault_id: session.vaultId,
      provider: params.provider,
    }).then(() => {
      queryClient.invalidateQueries({ queryKey: ["cloud"] });
      router.replace("/home" as any);
    }).catch((e: any) => {
      setSessionRestoreError(e?.response?.data?.error_msg || e?.message || "Could not switch cloud provider");
      handledConnectedCallback.current = false;
    }).finally(() => persistBindingMutation.reset());
  }, [session?.vaultId, params.cloud_connected, params.provider, pendingState]);

  // Allow pending Google callback without session (Case 1 cloud sync).
  // Without a selected vault, users belong on landing "/" — not vault-id login.
  useEffect(() => {
    if (!session && !isGoogleCallback) {
      router.replace("/" as any);
    }
  }, [session, isGoogleCallback]);

  // Root bootstrap intentionally pauses on OAuth callback URLs. Restore the
  // server session here for an existing vault so the chooser can continue.
  //
  // The ref guard is for StrictMode's double-invoked effects: the two writes are
  // idempotent, but two concurrent GET /session calls would be a wasted request
  // on every OAuth return, and one of them could land after the user has moved
  // on. It survives the simulated remount, so it means "once per mount".
  const restoredSession = useRef(false);
  useEffect(() => {
    if (session || !params.cloud_connected || pendingState) return;
    if (restoredSession.current) return;
    restoredSession.current = true;
    fetchSession()
      .then((s) => {
        selectVaultSession({ vaultId: s.vault_id, cryptoVersion: s.crypto_version });
        updateLockEpoch(s.lock_epoch ?? 0);
      })
      .catch((e) => setSessionRestoreError(e instanceof Error ? e.message : "Google sign-in session could not be restored"));
  }, [session, params.cloud_connected, pendingState]);

  const handleSelectVault = async (target: VaultSummary) => {
    if (!session) return;
    if (requiresSwitchConfirmation(session.vaultId, target)) {
      setSwitchTarget(target);
      setSwitchPassword("");
      setSwitchError(null);
      return;
    }
    await performOpen(target, undefined);
  };

  /**
   * M3: switching is atomic around the selected id.
   *
   * Three things guard against cross-vault contamination:
   *
   *  1. `guard` — captured before the network round-trip and re-checked after.
   *     If the user switched (or a peer did) while /auth + /get_vault were in
   *     flight, this result is stale and must be dropped rather than installed.
   *  2. `switchVaultOpen` — verifies the server authenticated the vault we
   *     asked for and that the document belongs to it, then commits selection +
   *     session + key + document + version in one state write.
   *  3. Store-side epoch — anything else async (sync, queries) checks it too.
   *
   * On any failure nothing is written, so the previous vault keeps its state
   * and the user sees a coherent locked-or-unlocked screen.
   */
  const performOpen = async (target: VaultSummary, password?: string) => {
    setSwitching(true);
    setSwitchError(null);
    const guard = captureSelectionEpoch();
    try {
      const previousVaultId = selectedVaultId(useAppStore.getState().vault);
      const result = await openVaultFlow({ vaultId: target.vault_id, masterPassword: password });

      // A switch happened while we were opening. Drop this result entirely —
      // installing it would put vault `target`'s key under whatever vault is
      // now selected.
      if (!guard.stillCurrent()) {
        console.warn("Vault open discarded: selection changed while opening", {
          requested: target.vault_id,
        });
        return;
      }

      // Abandon the old vault's ciphertext cache before the new document
      // lands. Its device records and OPFS file stay namespaced for its own
      // next unlock; initSQLite below releases the old handle. Icons are only
      // dropped from memory — the on-disk records stay namespaced per vault,
      // so switching back is instant and no icon can bleed across vaults.
      queryClient.removeQueries({ queryKey: ["vault"] });
      if (previousVaultId) forgetVaultFavicons(previousVaultId);
      queryClient.removeQueries({ queryKey: ["cloud"] });

      switchVaultOpen({
        requestedVaultId: target.vault_id,
        session: result.session,
        vaultKey: result.vaultKey,
        decryptedVault: result.decryptedVault,
        version: result.version,
        lockEpoch: result.lockEpoch,
      });

      await initSQLite(target.vault_id);
      await upsertVaultId(target.vault_id);
      await upsertVaultVersion(result.version);

      if (previousVaultId && previousVaultId !== target.vault_id) {
        // Tell other tabs to converge to the new vault (they re-check the
        // cookie authoritatively on receipt).
        const { postSessionEvent } = await import("@/src/lib/sync/session-channel");
        postSessionEvent("vault-switch", previousVaultId, null);
      }
      setSwitchTarget(null);
      router.replace("/home" as any);
    } catch (e) {
      console.error("Failed to open vault", e);
      setSwitchError(e instanceof Error ? e.message : "Failed to open vault");
    } finally {
      setSwitching(false);
    }
  };

  const handleGoogleVaultSelect = (gv: VaultDescriptor) => {
    setGoogleImportTarget(gv);
    setGoogleImportPassword("");
    setGoogleImportError(null);
  };

  const handleGoogleImportConfirm = async () => {
    if (!googleImportTarget) return;
    if (!googleImportPassword) {
      setGoogleImportError("Master password required");
      return;
    }
    const hasSession = !!session;
    if (!hasSession && pendingState) {
      setGoogleImporting(true);
      setGoogleImportError(null);
      // An import that races a switch would otherwise install the imported
      // vault's key under whatever is selected by the time it returns.
      const guard = captureSelectionEpoch();
      try {
        // Case 1 (no session): vault may only exist on Drive — fetch the package
        // via the pending token, verify the password locally, and register it
        // here with the recovery material the package already carries.
        const result = await importVaultFromCloud({
          vaultId: googleImportTarget.vault_id,
          fileId: googleImportTarget.file_id,
          masterPassword: googleImportPassword,
          pendingState,
        });
        if (!guard.stillCurrent()) {
          console.warn("Vault import discarded: selection changed during import");
          return;
        }

        switchVaultOpen({
          requestedVaultId: googleImportTarget.vault_id,
          session: result.session,
          vaultKey: result.vaultKey,
          decryptedVault: result.decryptedVault,
          version: result.version,
          lockEpoch: result.lockEpoch,
        });
        await initSQLite(googleImportTarget.vault_id);
        await upsertVaultId(googleImportTarget.vault_id);
        await upsertVaultVersion(result.version);
        try {
          await linkPendingMutation.mutateAsync(pendingState);
        } catch (e) {
          console.warn("Failed to link pending Google token", e);
        } finally {
          linkPendingMutation.reset();
        }
        // Persist the Drive binding. The imported package is the source of
        // truth for the local vault, and the server records it as the backup
        // watermark; from here the server mirrors committed writes to Drive.
        try {
          await persistBindingMutation.mutateAsync({
            vault_id: googleImportTarget.vault_id,
            remote_file_id: googleImportTarget.file_id,
            provider: params.provider ?? "google_drive",
          });
        } catch (e) {
          console.warn("Failed to persist Drive binding after import", e);
        } finally {
          persistBindingMutation.reset();
        }
        setGoogleImportTarget(null);
        // The vault now exists on this server (or already did). Recovery was
        // established at creation and travels in the package, so a restore never
        // pauses for a recovery step.
        router.replace("/home" as any);
        return;
      } catch (e: any) {
        const msg = e?.response?.data?.error_msg || e?.message || "Failed to import vault (pending flow)";
        if (msg.includes("Incorrect") || msg.includes("vault not found")) {
          setGoogleImportError("Incorrect master password or vault not found – existing vault untouched.");
        } else {
          setGoogleImportError(msg);
        }
        setGoogleImporting(false);
        return;
      } finally {
        setGoogleImporting(false);
      }
    }

    setGoogleImporting(true);
    setGoogleImportError(null);
    try {
      // The vault may already be on this server (normal password login) or exist
      // only as a provider package (verify + register here). Either way the
      // result is an unlocked session, and recovery already exists from
      // creation — there is no recovery step in an import.
      const result = await importVaultFromCloud({
        vaultId: googleImportTarget.vault_id,
        fileId: googleImportTarget.file_id,
        masterPassword: googleImportPassword,
        pendingState: pendingState || undefined,
      });

      // Atomic: selection + session + key + document in one write, verified
      // against the vault we asked to import. See `performOpen` for the full
      // reasoning — the same three guards apply to an import.
      switchVaultOpen({
        requestedVaultId: googleImportTarget.vault_id,
        session: result.session,
        vaultKey: result.vaultKey,
        decryptedVault: result.decryptedVault,
        version: result.version,
        lockEpoch: result.lockEpoch,
      });
      await initSQLite(googleImportTarget.vault_id);
      await upsertVaultId(googleImportTarget.vault_id);
      await upsertVaultVersion(result.version);
      setGoogleImportTarget(null);
      router.replace("/home" as any);
    } catch (e: any) {
      if (e?.message?.includes("Incorrect")) {
        setGoogleImportError("Incorrect master password – existing vault untouched. No vault found hint not revealed.");
      } else {
        setGoogleImportError(e?.message || "Failed to import vault");
      }
    } finally {
      setGoogleImporting(false);
    }
  };

  if (!session && !isGoogleCallback) {
    return (
      <View className="flex-1 items-center justify-center bg-ground">
        <ActivityIndicator color="#fff" />
      </View>
    );
  }

  const driveCount = googleVaults?.length ?? 0;
  const localCount = vaults?.length ?? 0;
  // Names are labels, not identity, so duplicates are legal. Where two local
  // entries would render identically (or a vault has no known name yet), show
  // the short id as secondary text; otherwise the UUID stays out of the way.
  const localVaultLabels = new Map((vaults ?? []).map((v) => [v.vault_id, displayVaultName(v.vault_id)]));
  const duplicatedNames = new Set(
    [...localVaultLabels.values()].filter((label, index, all) => all.indexOf(label) !== index),
  );

  return (
    <View className="flex-1 bg-ground px-6 py-8 items-center">
      {/* Header — back arrow returns to landing ("/"), never to OAuth */}
      <View className="w-full max-w-[880px]">
        <View className="flex-row items-center gap-3">
          <Pressable
            accessibilityLabel="Back to landing"
            accessibilityRole="button"
            className="h-8 w-8 items-center justify-center"
            onPress={() => router.replace("/" as any)}
          >
            <ArrowLeft size={24} color="#E5E7EB" />
          </Pressable>
          <Text className="text-primary-text text-2xl font-bold">Choose a vault</Text>
        </View>
        <Text className="text-muted-text text-sm mb-6 ml-11 mt-2">
          {driveCount} from Drive · {localCount} on this device
        </Text>
      </View>

      {/* Google Drive vaults — listed directly, no sign-in button */}
      <View className="w-full max-w-[880px] bg-panel rounded-xl p-5 mb-6 border border-border">
        <View className="flex-row items-center gap-2.5">
          <GoogleDriveIcon width={20} height={19} />
          <Text className="text-primary-text text-[15px] font-semibold">Google Drive vaults</Text>
        </View>
        {googleConfigured === false && (
          <Text className="text-muted-text text-xs mt-2">Not configured – see .env.example</Text>
        )}
        {params.cloud_error && (
          <View className="bg-red-900/20 border border-red-800 rounded-lg p-3 mt-3">
            <Text className="text-red-400 text-xs">Google error: {params.cloud_error}</Text>
            {params.cloud_error_detail && <Text className="text-red-300 text-xs mt-1">Details: {params.cloud_error_detail}</Text>}
          </View>
        )}
        {googleError && (
          <View className="bg-red-900/20 border border-red-800 rounded-lg p-3 mt-3">
            <Text className="text-red-400 text-xs">{googleError}</Text>
          </View>
        )}
        <View className="mt-3.5">
          {googleLoading ? (
            <ActivityIndicator color="#fff" />
          ) : googleVaults && googleVaults.length > 0 ? (
            googleVaults.map((gv) => (
              <Pressable key={gv.file_id} className="bg-card rounded-[10px] p-4 mb-2 border border-border-strong active:border-accent-line" onPress={() => handleGoogleVaultSelect(gv)}>
                <Text className="text-primary-text text-sm font-semibold">{displayVaultName(gv.vault_id)}</Text>
                <Text className="text-muted-text text-xs mt-1">{gv.modified_time ? new Date(gv.modified_time).toLocaleDateString() : ""} • {gv.size ? `${gv.size} bytes` : ""} • Rev {(gv.head_revision_id || gv.version || "").slice(0, 8)}</Text>
                <Text className="text-accent-text text-xs mt-1.5">Tap to download & enter master password to import</Text>
              </Pressable>
            ))
          ) : (
            !googleLoading && <Text className="text-muted-text text-xs">No Voult vaults found in this Google account.</Text>
          )}
        </View>
      </View>

      {/* Local vaults */}
      {loading ? (
        <View className="w-full max-w-[880px] items-center justify-center py-12">
          <ActivityIndicator color="#fff" />
          <Text className="text-muted-text mt-2">Loading vaults…</Text>
        </View>
      ) : error ? (
        <View className="w-full max-w-[880px] bg-red-900/20 border border-red-800 rounded-lg p-4">
          <Text className="text-red-400">{error}</Text>
        </View>
      ) : session && vaults && vaults.length > 0 ? (
        <ScrollView className="flex-1 w-full max-w-[880px]">
          <Text className="text-muted-text text-xs uppercase tracking-wider mb-2">Existing local vaults</Text>
          {vaults.map((v) => {
            const label = localVaultLabels.get(v.vault_id) ?? displayVaultName(v.vault_id);
            const showId = !hasKnownVaultName(v.vault_id) || duplicatedNames.has(label);
            return (
              <Pressable
                key={v.vault_id}
                className={`bg-card rounded-lg p-4 mb-3 border ${session.vaultId === v.vault_id ? "border-accent-line" : "border-border"}`}
                onPress={() => handleSelectVault(v)}
              >
                <View className="flex-row justify-between items-start">
                  <View className="flex-1">
                    <Text className="text-primary-text font-medium">{label}</Text>
                    {showId ? (
                      <Text className="text-muted-text text-xs mt-1">ID: {v.vault_id.slice(0, 12)}…</Text>
                    ) : null}
                    <Text className="text-muted-text text-xs mt-1">
                      Version {v.version} • {new Date(v.created_at).toLocaleDateString()}
                    </Text>
                  </View>
                  <View className={`px-2 py-1 rounded ${session.vaultId === v.vault_id ? "bg-accent-line" : "bg-surface"}`}>
                    <Text className={`text-xs ${session.vaultId === v.vault_id ? "text-primary-text" : "text-muted-text"}`}>
                      {session.vaultId === v.vault_id ? "Active" : "Open"}
                    </Text>
                  </View>
                </View>
                {session.vaultId === v.vault_id && (
                  <Text className="text-accent-text text-xs mt-2">Currently unlocked</Text>
                )}
              </Pressable>
            );
          })}
        </ScrollView>
      ) : session ? (
        <View className="w-full max-w-[880px] bg-card rounded-lg p-6 items-center border border-border">
          <Text className="text-muted-text text-center">No vaults on this device yet.</Text>
          <Text className="text-muted-text text-xs text-center mt-2">Create your first vault to start saving logins.</Text>
        </View>
      ) : null}

      {/* Switch warning modal */}
      <Modal visible={!!switchTarget} transparent animationType="fade">
        <View className="flex-1 bg-black/60 items-center justify-center px-6">
          <View className="bg-card rounded-xl p-6 w-full max-w-md border border-border">
            <Text className="text-primary-text text-lg font-bold mb-2">Switch vault?</Text>
            <Text className="text-muted-text text-sm mb-1">Vault B will be opened separately from your current vault.</Text>
            <Text className="text-muted-text text-sm mb-4">
              Current vault's data remains on its own database. Pending intents stay durable on the previous vault's file.
            </Text>
            {switchTarget && (
              <View className="bg-surface rounded-lg p-3 mb-4">
                <Text className="text-primary-text text-sm">Target: {displayVaultName(switchTarget.vault_id)}</Text>
              </View>
            )}
            <Text className="text-muted-text text-xs mb-4">If the vault is password-protected and device unlock fails, enter its master password.</Text>
            {switchError && <Text className="text-red-400 text-sm mb-3">{switchError}</Text>}
            <View className="flex-row justify-end space-x-3">
              <Pressable className="px-4 py-2 rounded-lg" onPress={() => setSwitchTarget(null)} disabled={switching}>
                <Text className="text-muted-text">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-surface border border-border-strong rounded-lg"
                onPress={() => switchTarget && performOpen(switchTarget, switchPassword || undefined)}
                disabled={switching}
              >
                <Text className="text-primary-text font-medium">{switching ? "Switching…" : "Switch vault"}</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>

      {/* Google Drive import modal */}
      <Modal visible={!!googleImportTarget} transparent animationType="fade">
        <View className="flex-1 bg-black/60 items-center justify-center px-6">
          <View className="bg-card rounded-xl p-6 w-full max-w-md border border-border">
            <Text className="text-primary-text text-lg font-bold mb-2">Import from Google Drive?</Text>
            <Text className="text-muted-text text-sm mb-1">This will download the encrypted vault and create a local copy.</Text>
            {googleImportTarget && (
              <View className="bg-surface rounded-lg p-3 mb-3">
                <Text className="text-primary-text text-sm">{displayVaultName(googleImportTarget.vault_id)}</Text>
                <Text className="text-muted-text text-xs">File {googleImportTarget.file_id.slice(0, 12)}… • {googleImportTarget.name}</Text>
              </View>
            )}
            <Text className="text-muted-text text-xs mb-2">Master password for this vault</Text>
            <TextField
              className="mb-3"
              placeholder="Enter vault master password"
              secureTextEntry
              value={googleImportPassword}
              onChangeText={setGoogleImportPassword}
            />
            <Text className="text-muted-text text-xs mb-3">Password is never sent to server or Google – unwrapping happens locally. Wrong password fails closed, existing vault untouched.</Text>
            {googleImportError && <Text className="text-red-400 text-sm mb-3">{googleImportError}</Text>}
            <View className="flex-row justify-end space-x-3">
              <Pressable className="px-4 py-2 rounded-lg" onPress={() => setGoogleImportTarget(null)} disabled={googleImporting}>
                <Text className="text-muted-text">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-surface border border-border-strong rounded-lg"
                onPress={handleGoogleImportConfirm}
                disabled={googleImporting || !googleImportPassword}
              >
                <Text className="text-primary-text font-medium">{googleImporting ? "Importing…" : "Import & open"}</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}
