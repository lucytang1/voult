import { useEffect, useState } from "react";
import { Pressable, Text, TextInput, View, Switch } from "react-native";
import { useRouter } from "expo-router";
import { setSession, setVaultKey, updateDecryptedVault, updateLockEpoch, updateVaultVersion } from "@/src/lib/state";
import { createVaultFlow } from "@/src/lib/vault/create";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { upsertVaultId, upsertVaultVersion } from "@/src/lib/sqlite/web/services/client-state-service";
import { v4 as uuidv4 } from "uuid";
import { getGoogleStatus } from "@/src/lib/google/api";
import { enableGoogleDriveForVault } from "@/src/lib/google/enableSync";

/**
 * Create new local vault — Case 1 main entry (no session) and also for
 * already-authenticated users who want an additional vault.
 * Flow: enter master password -> vault created locally (can enable Drive later).
 * No vault-id input. Accessible without a session.
 */
export default function CreateVault() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [connectDrive, setConnectDrive] = useState(false);
  const [googleConfigured, setGoogleConfigured] = useState<boolean | null>(null);
  const [googleConnected, setGoogleConnected] = useState<boolean>(false);

  useEffect(() => {
    // Check if Google Drive is configured and connected (local Rust server)
    getGoogleStatus()
      .then((s) => {
        setGoogleConfigured(true);
        setGoogleConnected(s.connected);
      })
      .catch((e: any) => {
        const code = e?.response?.data?.code as string | undefined;
        if (code === "GOOGLE_NOT_CONFIGURED") {
          setGoogleConfigured(false);
        } else {
          setGoogleConfigured(true);
          setGoogleConnected(false);
        }
      });
  }, []);

  const canSubmit = password.length >= 8 && password === confirm && !creating;

  const [phase, setPhase] = useState<"idle" | "creatingLocal" | "authorizing" | "creatingRemote" | "verifying">("idle");

  const onCreate = async () => {
    if (!canSubmit) {
      if (password !== confirm) setError("Passwords do not match.");
      else if (password.length < 8) setError("Master password must be at least 8 characters.");
      return;
    }
    setError(null);
    setCreating(true);
    setPhase("creatingLocal");
    try {
      // §6.2: Complete local vault creation exactly as in §6.1 before Google.
      const starter = { items: [] as { id: string; site: string; username: string; password: string }[] };
      const created = await createVaultFlow(password, starter);
      const vaultId = created.vaultId;
      // Wire the newly created vault into local state and open its store so
      // /home has a valid session + database.
      setVaultKey(created.vaultKey);
      setSession(created.session);
      updateLockEpoch(created.lockEpoch);
      updateDecryptedVault(created.decryptedVault);
      updateVaultVersion(created.version);
      await initSQLite(vaultId);
      await upsertVaultId(vaultId);
      await upsertVaultVersion(created.version);
      // If user opted to connect Google Drive now (§6.2), continue to remote
      if (connectDrive && googleConfigured) {
        setPhase("authorizing");
        try {
          setPhase("creatingRemote");
          await enableGoogleDriveForVault(vaultId);
          setPhase("verifying");
          // Brief verify pause – enable already does read-back validation
          setPhase("idle");
        } catch (e: any) {
          // Keep local vault intact, offer retry/continue local-only per spec §6.2
          const msg = e?.message || String(e);
          if (msg.includes("Redirecting")) {
            // OAuth redirect already initiated – keep vault usable
            setPhase("authorizing");
            return;
          }
          console.warn("Google Drive connect failed, keeping local vault", e);
          setError(`Vault created locally, but Google Drive sync failed: ${msg}. You can retry via Home → Enable Google Drive sync.`);
          setPhase("idle");
          setTimeout(() => router.replace("/home" as any), 2000);
          return;
        }
      }
      setPhase("idle");
      router.replace("/home" as any);
    } catch (e) {
      console.error("Create vault failed", e);
      setError(e instanceof Error ? e.message : "Failed to create vault");
      setPhase("idle");
    } finally {
      setCreating(false);
    }
  };

  return (
    <View className="flex-1 bg-black px-6 py-8">
      <Text className="text-white text-2xl font-bold mb-2">Create new vault</Text>
      <Text className="text-gray-400 text-sm mb-1">This vault exists only on this device.</Text>
      <Text className="text-gray-500 text-xs mb-6">Until you enable Google Drive sync, it will not be available on other devices. You can enable sync later from Settings.</Text>

      <Text className="text-gray-300 text-sm mb-2">Master password</Text>
      <TextInput
        className="w-full rounded-lg bg-[#1e1e36] border border-[#2a2a4a] px-4 py-3 text-white mb-3"
        placeholder="Enter master password (≥8 chars)"
        placeholderTextColor="#666"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
      />
      <TextInput
        className="w-full rounded-lg bg-[#1e1e36] border border-[#2a2a4a] px-4 py-3 text-white mb-4"
        placeholder="Confirm master password"
        placeholderTextColor="#666"
        secureTextEntry
        value={confirm}
        onChangeText={setConfirm}
      />

      {/* Phase 3: Google Drive option – only shown if server is configured */}
      {googleConfigured === true && (
        <View className="flex-row items-center justify-between bg-[#1e1e36] rounded-lg p-3 mb-4 border border-[#2a2a4a]">
          <View className="flex-1 pr-3">
            <Text className="text-white text-sm font-medium">Back up to Google Drive</Text>
            <Text className="text-gray-400 text-xs mt-1">
              {googleConnected ? "Will create encrypted backup in Google Drive's appDataFolder" : "Will ask to sign in to Google after creating vault"}
            </Text>
          </View>
          <Switch
            value={connectDrive}
            onValueChange={setConnectDrive}
            trackColor={{ false: "#2a2a4a", true: "#7c3aed" }}
            thumbColor={connectDrive ? "#fff" : "#9ca3af"}
          />
        </View>
      )}
      {googleConfigured === false && (
        <View className="bg-[#1e1e36] rounded-lg p-3 mb-4 border border-[#2a2a4a] opacity-60">
          <Text className="text-gray-500 text-xs">Google Drive not configured on this server. Set GOOGLE_CLIENT_ID/SECRET in .env – see .env.example</Text>
        </View>
      )}

      <Pressable
        className={`w-full rounded-lg py-3 items-center ${canSubmit ? "bg-purple-600" : "bg-[#2a2a4a]"}`}
        onPress={onCreate}
        disabled={!canSubmit}
      >
        <Text className={`${canSubmit ? "text-white" : "text-gray-500"} font-medium`}>
          {phase === "creatingLocal" ? "Creating vault…" : phase === "authorizing" ? "Authorizing Google…" : phase === "creatingRemote" ? "Creating Drive file…" : phase === "verifying" ? "Verifying…" : connectDrive ? "Create & connect" : "Create vault"}
        </Text>
      </Pressable>

      {creating && phase !== "idle" && (
        <Text className="text-purple-300 text-xs mt-2 text-center">
          {phase === "creatingLocal" && "Local vault is being created first – it will be usable even if Google fails."}
          {phase === "creatingRemote" && "Uploading encrypted package to Drive appDataFolder as voult-vault-<vault_id>.json"}
          {phase === "verifying" && "Reading back file to verify vault_id and package integrity before marking cloud-backed."}
        </Text>
      )}

      {error && <Text className="text-red-400 text-sm mt-3">{error}</Text>}

      <Pressable className="mt-4 items-center" onPress={() => router.back()}>
        <Text className="text-gray-400">Cancel</Text>
      </Pressable>

      <View className="mt-8 bg-[#1e1e36] rounded-lg p-4 border border-[#2a2a4a]">
        <Text className="text-gray-400 text-xs">Vault ID will be generated securely on this device and never derived from your email or password. Each vault is independent – same email with different master passwords creates different vaults.</Text>
      </View>
    </View>
  );
}
