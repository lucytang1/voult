import { useState } from "react";
import { Pressable, Text, TextInput, View, Switch } from "react-native";
import { useRouter } from "expo-router";
import { selectVaultSession, commitVaultUnlock, updateDecryptedVault, updateLockEpoch, updateVaultVersion } from "@/src/lib/state";
import { createVaultFlow } from "@/src/lib/vault/create";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { upsertVaultId, upsertVaultVersion } from "@/src/lib/sqlite/web/services/client-state-service";
import { v4 as uuidv4 } from "uuid";
import { useCloudProviders, useCloudStatus } from "@/src/lib/cloud/queries";
import { useAppStore } from "@/src/lib/state";
import type { VaultItem } from "@/src/lib/state/type";
import { useSignUp } from "@/src/lib/queries/SignUp/query";
import { enableCloudForVault } from "@/src/lib/cloud/enableSync";
import { providerLabelForKind } from "@/src/lib/cloud/providers";

/**
 * Create new local vault — Case 1 main entry (no session) and also for
 * already-authenticated users who want an additional vault.
 * Flow: enter master password -> vault created locally (cloud backup can be enabled later).
 * No vault-id input. Accessible without a session.
 */
export default function CreateVault() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [connectDrive, setConnectDrive] = useState(false);
  const [chosenProvider, setChosenProvider] = useState<string | null>(null);
  const currentVaultId = useAppStore((s) => s.session?.vaultId);
  const googleStatusQuery = useCloudStatus(currentVaultId ?? "anonymous");
  const providersQuery = useCloudProviders();
  const googleConfigured = providersQuery.isSuccess ? providersQuery.data.length > 0 : null;
  const chosenProviderKind = chosenProvider ?? providersQuery.data?.[0]?.kind;
  const googleConnected = googleStatusQuery.data?.connected ?? false;

  const canSubmit = password.length >= 8 && password === confirm && !creating;

  const [phase, setPhase] = useState<"idle" | "creatingLocal" | "authorizing" | "creatingRemote" | "verifying">("idle");
  const signupMutation = useSignUp();

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
      // §6.2: Complete local vault creation first; cloud backup is optional.
      const starter = { items: [] as VaultItem[] };
      const created = await createVaultFlow(password, starter, signupMutation.mutateAsync);
      const vaultId = created.vaultId;
      // Wire the newly created vault into local state and open its store so
      // /home has a valid session + database.
      selectVaultSession(created.session);
      commitVaultUnlock(created.vaultKey);
      updateLockEpoch(created.lockEpoch);
      updateDecryptedVault(created.decryptedVault);
      updateVaultVersion(created.version);
      await initSQLite(vaultId);
      await upsertVaultId(vaultId);
      await upsertVaultVersion(created.version);
      // If user opted to connect cloud provider now (§6.2), continue to remote
      if (connectDrive && googleConfigured) {
        setPhase("authorizing");
        try {
          setPhase("creatingRemote");
          if (!chosenProviderKind) throw new Error("Cloud backup is not configured on this server.");
          await enableCloudForVault(vaultId, chosenProviderKind);
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
          console.warn("cloud provider connect failed, keeping local vault", e);
          setError(`Vault created locally, but cloud backup failed: ${msg}. You can retry via Home → Enable cloud backup.`);
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
      signupMutation.reset();
      setCreating(false);
    }
  };

  return (
    <View className="flex-1 bg-ground px-6 py-8">
      <Text className="text-primary-text text-2xl font-bold mb-2">Create new vault</Text>
      <Text className="text-muted-text text-sm mb-1">This vault exists only on this device.</Text>
      <Text className="text-muted-text text-xs mb-6">Until you enable cloud backup, it will not be available on other devices. You can enable sync later from Settings.</Text>

      <Text className="text-muted-text text-sm mb-2">Master password</Text>
      <TextInput
        className="w-full rounded-lg bg-card border border-border px-4 py-3 text-primary-text mb-3"
        placeholder="Enter master password (≥8 chars)"
        placeholderTextColor="#666"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
      />
      <TextInput
        className="w-full rounded-lg bg-card border border-border px-4 py-3 text-primary-text mb-4"
        placeholder="Confirm master password"
        placeholderTextColor="#666"
        secureTextEntry
        value={confirm}
        onChangeText={setConfirm}
      />

      {/* Keep local creation first, then let the user choose a configured provider. */}
      {googleConfigured === true && (
        <View className="bg-card rounded-lg p-3 mb-4 border border-border">
          <View className="flex-row items-center justify-between">
            <View className="flex-1 pr-3">
              <Text className="text-primary-text text-sm font-medium">Back up to a cloud provider</Text>
              <Text className="text-muted-text text-xs mt-1">
              {googleConnected ? "Use the connected account or authorize another provider." : "Sign in to the selected provider after creating the local vault."}
              </Text>
            </View>
            <Switch
              value={connectDrive}
              onValueChange={setConnectDrive}
              trackColor={{ false: "#4A2E4E", true: "#7C2A63" }}
              thumbColor={connectDrive ? "#F2F4F7" : "#7E8590"}
            />
          </View>
          {connectDrive && <View className="mt-3 gap-2">{providersQuery.data?.map((provider) => <Pressable key={provider.kind}
            accessibilityRole="button" accessibilityState={{ selected: chosenProviderKind === provider.kind }}
            onPress={() => setChosenProvider(provider.kind)}
            className={`rounded-lg border px-3 py-2 ${chosenProviderKind === provider.kind ? "border-accent-line bg-surface" : "border-border"}`}>
            <Text className="text-sm text-primary-text">{providerLabelForKind(provider.kind)}</Text>
          </Pressable>)}</View>}
        </View>
      )}
      {googleConfigured === false && (
        <View className="bg-card rounded-lg p-3 mb-4 border border-border opacity-60">
          <Text className="text-muted-text text-xs">Cloud backup is not configured on this server. See .env.example.</Text>
        </View>
      )}

      <Pressable
        className={`w-full rounded-lg py-3 items-center ${canSubmit ? "bg-accent-line" : "bg-surface"}`}
        onPress={onCreate}
        disabled={!canSubmit}
      >
        <Text className={`${canSubmit ? "text-primary-text" : "text-muted-text"} font-medium`}>
          {phase === "creatingLocal" ? "Creating vault…" : phase === "authorizing" ? "Authorizing…" : phase === "creatingRemote" ? "Creating provider file…" : phase === "verifying" ? "Verifying…" : connectDrive ? "Create & connect" : "Create vault"}
        </Text>
      </Pressable>

      {creating && phase !== "idle" && (
        <Text className="text-accent-text text-xs mt-2 text-center">
          {phase === "creatingLocal" && "Local vault is being created first – it will be usable even if cloud provider fails."}
          {phase === "creatingRemote" && "Uploading encrypted package to provider app folder as voult-vault-<vault_id>.json"}
          {phase === "verifying" && "Reading back file to verify vault_id and package integrity before marking cloud-backed."}
        </Text>
      )}

      {error && <Text className="text-red-400 text-sm mt-3">{error}</Text>}

      <Pressable className="mt-4 items-center" onPress={() => router.back()}>
        <Text className="text-muted-text">Cancel</Text>
      </Pressable>

      <View className="mt-8 bg-card rounded-lg p-4 border border-border">
        <Text className="text-muted-text text-xs">Vault ID will be generated securely on this device and never derived from your email or password. Each vault is independent – same email with different master passwords creates different vaults.</Text>
      </View>
    </View>
  );
}
