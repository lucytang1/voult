import { useEffect, useState } from "react";
import { Pressable, Text, View, ScrollView, Modal, ActivityIndicator, TextInput } from "react-native";
import { useRouter, useLocalSearchParams } from "expo-router";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { useAppStore, setSession, setVaultKey, updateDecryptedVault, updateLockEpoch, updateVaultVersion } from "@/src/lib/state";
import { listVaults, VaultSummary } from "@/src/lib/queries/vaults/query";
import { openVaultFlow, requiresSwitchConfirmation } from "@/src/lib/vault/open";
import { getGoogleStatus, listGoogleVaults, listGoogleVaultsPending } from "@/src/lib/google/api";
import { GoogleDriveIcon } from "../../../assets/images/GoogleDriveIcon";
import type { VaultDescriptor } from "@/src/lib/google/api";
import { importVaultFromGoogle } from "@/src/lib/vault/import";
import { fetchSession } from "@/src/lib/queries/session/query";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { upsertVaultId, upsertVaultVersion } from "@/src/lib/sqlite/web/services/client-state-service";

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

  const [vaults, setVaults] = useState<VaultSummary[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [switchTarget, setSwitchTarget] = useState<VaultSummary | null>(null);
  const [switchPassword, setSwitchPassword] = useState("");
  const [switching, setSwitching] = useState(false);
  const [switchError, setSwitchError] = useState<string | null>(null);

  // Google Drive state
  const [googleStatus, setGoogleStatus] = useState<{ connected: boolean; email?: string } | null>(null);
  const [googleConfigured, setGoogleConfigured] = useState<boolean | null>(null);
  const [googleVaults, setGoogleVaults] = useState<VaultDescriptor[] | null>(null);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [googleError, setGoogleError] = useState<string | null>(null);
  const [googleImportTarget, setGoogleImportTarget] = useState<VaultDescriptor | null>(null);
  const [googleImportPassword, setGoogleImportPassword] = useState("");
  const [googleImportError, setGoogleImportError] = useState<string | null>(null);
  const [googleImporting, setGoogleImporting] = useState(false);
  const params = useLocalSearchParams<{ google_connected?: string; google_error?: string; google_error_detail?: string; google_pending_state?: string }>();
  const pendingState = (params as any).google_pending_state as string | undefined
    || (typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("google_pending_state") || undefined : undefined);
  const isGoogleCallback = !!pendingState || !!params.google_connected || !!params.google_error;

  // Allow pending Google callback without session (Case 1 cloud sync).
  // Otherwise unauthenticated users belong on landing "/" — not vault-id login.
  useEffect(() => {
    if (!session && !isGoogleCallback) {
      router.replace("/" as any);
    }
  }, [session, isGoogleCallback]);

  // Root bootstrap intentionally pauses on OAuth callback URLs. Restore the
  // server session here for an existing vault so the chooser can continue.
  useEffect(() => {
    if (session || !params.google_connected || pendingState) return;
    fetchSession()
      .then((s) => {
        setSession({ vaultId: s.vault_id, cryptoVersion: s.crypto_version });
        updateLockEpoch(s.lock_epoch ?? 0);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Google sign-in session could not be restored"));
  }, [session, params.google_connected, pendingState]);

  // Refresh Google status on mount and after OAuth callback
  const refreshGoogleStatus = async () => {
    try {
      const s = await getGoogleStatus();
      setGoogleStatus({ connected: s.connected, email: s.email });
      setGoogleConfigured(true);
      return s;
    } catch (e: any) {
      const code = e?.response?.data?.code as string | undefined;
      if (code === "GOOGLE_NOT_CONFIGURED") {
        setGoogleConfigured(false);
        setGoogleStatus(null);
      } else {
        setGoogleConfigured(true);
        setGoogleStatus({ connected: false });
      }
      return null;
    }
  };

  // Handle pending Google auth (unified flow for new vault without local session)
  useEffect(() => {
    if (!pendingState) return;
    setGoogleLoading(true);
    listGoogleVaultsPending(pendingState)
      .then((v) => { setGoogleVaults(v); setGoogleError(null); })
      .catch((e: any) => { setGoogleError(e?.response?.data?.error_msg || e?.message || "Failed to list Drive vaults (pending)"); })
      .finally(() => setGoogleLoading(false));
  }, [pendingState]);

  useEffect(() => {
    refreshGoogleStatus();
    if (params.google_connected || params.google_error) {
      refreshGoogleStatus();
    }
  }, []);

  // The chooser is reached via "Continue with Google Drive", so Drive vaults
  // are listed directly — no intermediate sign-in button. Fetch them as soon
  // as the session-based connection is confirmed (the pending OAuth flow
  // above covers the no-session case).
  useEffect(() => {
    if (pendingState || !googleStatus?.connected) return;
    let cancelled = false;
    setGoogleLoading(true);
    listGoogleVaults()
      .then((v) => { if (!cancelled) { setGoogleVaults(v); setGoogleError(null); } })
      .catch((e: any) => { if (!cancelled) setGoogleError(e?.response?.data?.error_msg || e?.message || "Failed to list Drive vaults"); })
      .finally(() => { if (!cancelled) setGoogleLoading(false); });
    return () => { cancelled = true; };
  }, [googleStatus?.connected, pendingState]);

  useEffect(() => {
    if (!session) return;
    setLoading(true);
    listVaults()
      .then((v) => { setVaults(v); setError(null); })
      .catch((e) => { console.error("Failed to list vaults", e); setError(e instanceof Error ? e.message : "Failed to load vaults"); })
      .finally(() => setLoading(false));
  }, [session?.vaultId]);

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

  const performOpen = async (target: VaultSummary, password?: string) => {
    setSwitching(true);
    setSwitchError(null);
    try {
      const previousVaultId = session?.vaultId ?? null;
      const result = await openVaultFlow({ vaultId: target.vault_id, masterPassword: password });
      // Single-vault invariant: opening a different vault abandons the old
      // one's in-memory state and ciphertext cache (its device records and
      // OPFS file stay namespaced for its next unlock). initSQLite releases
      // the old handle before opening the new file.
      queryClient.removeQueries({ queryKey: ["vault"] });
      setVaultKey(result.vaultKey);
      setSession(result.session);
      updateLockEpoch(result.lockEpoch);
      updateDecryptedVault(result.decryptedVault);
      updateVaultVersion(result.version);
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
      try {
        // Case 1 (no session): vault may only exist on Drive — fetch package
        // via pending token, verify password locally, register on this server.
        const result = await importVaultFromGoogle({
          vaultId: googleImportTarget.vault_id,
          fileId: googleImportTarget.file_id,
          masterPassword: googleImportPassword,
          pendingState,
        });
        setVaultKey(result.vaultKey);
        setSession(result.session);
        updateLockEpoch(result.lockEpoch);
        updateDecryptedVault(result.decryptedVault);
        updateVaultVersion(result.version);
        await initSQLite(googleImportTarget.vault_id);
        await upsertVaultId(googleImportTarget.vault_id);
        await upsertVaultVersion(result.version);
        try {
          await httpPostLinkPending(pendingState);
        } catch (e) {
          console.warn("Failed to link pending Google token", e);
        }
        // Persist Drive binding so future sync uses GoogleRemote.
        try {
          const { http } = await import("@/src/lib/queries/http");
          await http.post("/google/binding", {
            vault_id: googleImportTarget.vault_id,
            drive_file_id: googleImportTarget.file_id,
          });
        } catch (e) {
          console.warn("Failed to persist Drive binding after import", e);
        }
        setGoogleImportTarget(null);
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
      const result = await importVaultFromGoogle({
        vaultId: googleImportTarget.vault_id,
        fileId: googleImportTarget.file_id,
        masterPassword: googleImportPassword,
        pendingState: pendingState || undefined,
      });
      setVaultKey(result.vaultKey);
      setSession(result.session);
      updateLockEpoch(result.lockEpoch);
      updateDecryptedVault(result.decryptedVault);
      updateVaultVersion(result.version);
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

  async function httpPostLinkPending(state: string) {
    const { http } = await import("@/src/lib/queries/http");
    await http.post("/google/link-pending", { state });
  }

  if (!session && !isGoogleCallback) {
    return (
      <View className="flex-1 items-center justify-center bg-black">
        <ActivityIndicator color="#fff" />
      </View>
    );
  }

  const driveCount = googleVaults?.length ?? 0;
  const localCount = vaults?.length ?? 0;

  return (
    <View className="flex-1 bg-black px-6 py-8 items-center">
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
          <Text className="text-white text-2xl font-bold">Choose a vault</Text>
        </View>
        <Text className="text-gray-400 text-sm mb-6 ml-11 mt-2">
          {driveCount} from Drive · {localCount} on this device
        </Text>
      </View>

      {/* Google Drive vaults — listed directly, no sign-in button */}
      <View className="w-full max-w-[880px] bg-[#1a1a2e] rounded-xl p-5 mb-6 border border-[#2a2a4a]">
        <View className="flex-row items-center gap-2.5">
          <GoogleDriveIcon width={20} height={19} />
          <Text className="text-white text-[15px] font-semibold">Google Drive vaults</Text>
        </View>
        {googleConfigured === false && (
          <Text className="text-gray-500 text-xs mt-2">Not configured – see .env.example</Text>
        )}
        {params.google_error && (
          <View className="bg-red-900/20 border border-red-800 rounded-lg p-3 mt-3">
            <Text className="text-red-400 text-xs">Google error: {params.google_error}</Text>
            {params.google_error_detail && <Text className="text-red-300 text-xs mt-1">Details: {params.google_error_detail}</Text>}
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
              <Pressable key={gv.file_id} className="bg-[#23233f] rounded-[10px] p-4 mb-2 border border-[#3a3a5a] active:border-purple-600" onPress={() => handleGoogleVaultSelect(gv)}>
                <Text className="text-white text-sm font-semibold">Vault {gv.vault_id.slice(0, 8)}… — {gv.name}</Text>
                <Text className="text-gray-400 text-xs mt-1">{gv.modified_time ? new Date(gv.modified_time).toLocaleDateString() : ""} • {gv.size ? `${gv.size} bytes` : ""} • Rev {(gv.head_revision_id || gv.version || "").slice(0, 8)}</Text>
                <Text className="text-purple-300 text-xs mt-1.5">Tap to download & enter master password to import</Text>
              </Pressable>
            ))
          ) : (
            !googleLoading && <Text className="text-gray-400 text-xs">No Voult vaults found in this Google account.</Text>
          )}
        </View>
      </View>

      {/* Local vaults */}
      {loading ? (
        <View className="w-full max-w-[880px] items-center justify-center py-12">
          <ActivityIndicator color="#fff" />
          <Text className="text-gray-400 mt-2">Loading vaults…</Text>
        </View>
      ) : error ? (
        <View className="w-full max-w-[880px] bg-red-900/20 border border-red-800 rounded-lg p-4">
          <Text className="text-red-400">{error}</Text>
        </View>
      ) : session && vaults && vaults.length > 0 ? (
        <ScrollView className="flex-1 w-full max-w-[880px]">
          <Text className="text-gray-400 text-xs uppercase tracking-wider mb-2">Existing local vaults</Text>
          {vaults.map((v) => (
            <Pressable
              key={v.vault_id}
              className={`bg-[#1e1e36] rounded-lg p-4 mb-3 border ${session.vaultId === v.vault_id ? "border-purple-600" : "border-[#2a2a4a]"}`}
              onPress={() => handleSelectVault(v)}
            >
              <View className="flex-row justify-between items-start">
                <View className="flex-1">
                  <Text className="text-white font-medium">Vault {v.vault_id.slice(0, 8)}…</Text>
                  <Text className="text-gray-500 text-xs mt-1">ID: {v.vault_id.slice(0, 12)}…</Text>
                  <Text className="text-gray-400 text-xs mt-1">
                    Version {v.version} • {new Date(v.created_at).toLocaleDateString()}
                  </Text>
                </View>
                <View className={`px-2 py-1 rounded ${session.vaultId === v.vault_id ? "bg-purple-600" : "bg-[#2a2a4a]"}`}>
                  <Text className={`text-xs ${session.vaultId === v.vault_id ? "text-white" : "text-gray-300"}`}>
                    {session.vaultId === v.vault_id ? "Active" : "Open"}
                  </Text>
                </View>
              </View>
              {session.vaultId === v.vault_id && (
                <Text className="text-purple-300 text-xs mt-2">Currently unlocked</Text>
              )}
            </Pressable>
          ))}
        </ScrollView>
      ) : session ? (
        <View className="w-full max-w-[880px] bg-[#1e1e36] rounded-lg p-6 items-center border border-[#2a2a4a]">
          <Text className="text-gray-400 text-center">No vaults on this device yet.</Text>
          <Text className="text-gray-500 text-xs text-center mt-2">Create your first vault to start saving logins.</Text>
        </View>
      ) : null}

      {/* Switch warning modal */}
      <Modal visible={!!switchTarget} transparent animationType="fade">
        <View className="flex-1 bg-black/60 items-center justify-center px-6">
          <View className="bg-[#1e1e36] rounded-xl p-6 w-full max-w-md border border-[#2a2a4a]">
            <Text className="text-white text-lg font-bold mb-2">Switch vault?</Text>
            <Text className="text-gray-400 text-sm mb-1">Vault B will be opened separately from your current vault.</Text>
            <Text className="text-gray-400 text-sm mb-4">
              Current vault's data remains on its own database. Pending intents stay durable on the previous vault's file.
            </Text>
            {switchTarget && (
              <View className="bg-[#2a2a4a] rounded-lg p-3 mb-4">
                <Text className="text-white text-sm">Target: {switchTarget.vault_id.slice(0, 12)}…</Text>
              </View>
            )}
            <Text className="text-gray-500 text-xs mb-4">If the vault is password-protected and device unlock fails, enter its master password.</Text>
            {switchError && <Text className="text-red-400 text-sm mb-3">{switchError}</Text>}
            <View className="flex-row justify-end space-x-3">
              <Pressable className="px-4 py-2 rounded-lg" onPress={() => setSwitchTarget(null)} disabled={switching}>
                <Text className="text-gray-400">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-purple-600 rounded-lg"
                onPress={() => switchTarget && performOpen(switchTarget, switchPassword || undefined)}
                disabled={switching}
              >
                <Text className="text-white font-medium">{switching ? "Switching…" : "Switch vault"}</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>

      {/* Google Drive import modal */}
      <Modal visible={!!googleImportTarget} transparent animationType="fade">
        <View className="flex-1 bg-black/60 items-center justify-center px-6">
          <View className="bg-[#1e1e36] rounded-xl p-6 w-full max-w-md border border-[#2a2a4a]">
            <Text className="text-white text-lg font-bold mb-2">Import from Google Drive?</Text>
            <Text className="text-gray-400 text-sm mb-1">This will download the encrypted vault and create a local copy.</Text>
            {googleImportTarget && (
              <View className="bg-[#2a2a4a] rounded-lg p-3 mb-3">
                <Text className="text-white text-sm">Vault {googleImportTarget.vault_id.slice(0, 12)}…</Text>
                <Text className="text-gray-400 text-xs">File {googleImportTarget.file_id.slice(0, 12)}… • {googleImportTarget.name}</Text>
              </View>
            )}
            <Text className="text-gray-300 text-xs mb-2">Master password for this vault</Text>
            <TextInput
              className="w-full rounded-lg bg-[#2a2a4a] px-3 py-2 text-white mb-3 border border-[#3a3a5a]"
              placeholder="Enter vault master password"
              placeholderTextColor="#666"
              secureTextEntry
              value={googleImportPassword}
              onChangeText={setGoogleImportPassword}
            />
            <Text className="text-gray-500 text-xs mb-3">Password is never sent to server or Google – unwrapping happens locally. Wrong password fails closed, existing vault untouched.</Text>
            {googleImportError && <Text className="text-red-400 text-sm mb-3">{googleImportError}</Text>}
            <View className="flex-row justify-end space-x-3">
              <Pressable className="px-4 py-2 rounded-lg" onPress={() => setGoogleImportTarget(null)} disabled={googleImporting}>
                <Text className="text-gray-400">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-purple-600 rounded-lg"
                onPress={handleGoogleImportConfirm}
                disabled={googleImporting || !googleImportPassword}
              >
                <Text className="text-white font-medium">{googleImporting ? "Importing…" : "Import & open"}</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}
