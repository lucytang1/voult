import { useState } from "react";
import { Pressable, Text, TextInput, View, Switch } from "react-native";
import { useRouter } from "expo-router";
import { selectVaultSession, commitVaultUnlock, updateDecryptedVault, updateLockEpoch, updateVaultVersion } from "@/src/lib/state";
import { prepareVaultFlow, type CreateVaultResult } from "@/src/lib/vault/create";
import { commitVaultRegistration, describeCommitError, type PendingVaultRegistration } from "@/src/lib/vault/registration";
import { persistDeviceSecrets } from "@/src/lib/auth/utils";
import { RecoveryKeyInterstitial } from "@/src/lib/components/recovery-key-interstitial";
import { VaultNameStep } from "@/src/lib/components/vault-name-step";
import { DEFAULT_VAULT_NAME } from "@/src/lib/vault/name";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { upsertVaultId, upsertVaultVersion } from "@/src/lib/sqlite/web/services/client-state-service";
import { useCloudProviders, useCloudStatus } from "@/src/lib/cloud/queries";
import { useAppStore } from "@/src/lib/state";
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
  // Onboarding step: master password -> name -> recovery file. The name is
  // pre-filled, so a user who does not care can press Continue straight away.
  const [step, setStep] = useState<"password" | "name">("password");
  const [vaultName, setVaultName] = useState(DEFAULT_VAULT_NAME);
  const currentVaultId = useAppStore((s) => s.session?.vaultId);
  const googleStatusQuery = useCloudStatus(currentVaultId ?? "anonymous");
  const providersQuery = useCloudProviders();
  const googleConfigured = providersQuery.isSuccess ? providersQuery.data.length > 0 : null;
  const chosenProviderKind = chosenProvider ?? providersQuery.data?.[0]?.kind;
  const googleConnected = googleStatusQuery.data?.connected ?? false;

  const canSubmit = password.length >= 8 && password === confirm && !creating;

  const [phase, setPhase] = useState<"idle" | "creatingLocal" | "showingRecoveryKey" | "authorizing" | "creatingRemote" | "verifying">("idle");
  const signupMutation = useSignUp();
  // The vault, fully derived but NOT yet registered. Nothing about it exists on
  // the server while this is set — that is the point. The interstitial is where
  // the user gets the recovery file, and pressing Continue is what registers it.
  const [prepared, setPrepared] = useState<PendingVaultRegistration | null>(null);
  // Set the moment /register succeeds, so a retry after a local-setup failure
  // does not register a second time.
  const [committed, setCommitted] = useState<CreateVaultResult | null>(null);

  /**
   * Second half of creation, run once the vault is registered and the user has
   * the recovery file.
   *
   * The device key is enrolled HERE and not in `prepareVaultFlow`, so a vault
   * never ends up with a working device key but a recovery file nobody saved.
   */
  const finishCreation = async (result: CreateVaultResult, connectDrive: boolean) => {
    const vaultId = result.session.vaultId;
    // Give this device a key so the next unlock is a local unwrap.
    await persistDeviceSecrets(result.vaultKeyRaw, vaultId);
    // Wire the newly created vault into local state and open its store so
    // /home has a valid session + database.
    selectVaultSession(result.session);
    commitVaultUnlock(result.vaultKey);
    updateLockEpoch(result.lockEpoch);
    updateDecryptedVault(result.decryptedVault);
    updateVaultVersion(result.version);
    await initSQLite(vaultId);
    await upsertVaultId(vaultId);
    await upsertVaultVersion(result.version);
    // The raw key bytes are no longer needed; drop our reference so they can be
    // collected now rather than at some indeterminate later point.
    result.vaultKeyRaw.fill(0);
    setPrepared(null);

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
  };

  const goToName = () => {
    if (!canSubmit) {
      if (password !== confirm) setError("Passwords do not match.");
      else if (password.length < 8) setError("Master password must be at least 8 characters.");
      return;
    }
    setError(null);
    setStep("name");
  };

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
      // §6.2: local preparation first; cloud backup is optional.
      //
      // Nothing is registered here. The vault id, both envelopes and the
      // recovery secret are all derived locally, and the server hears about
      // this vault only when the user continues past the interstitial with the
      // recovery file in hand.
      // A new vault is created EMPTY: no demo entries, no seeded credentials.
      // Everything the vault holds is something the user added themselves.
      const prepared = await prepareVaultFlow(password, vaultName);
      setPrepared(prepared);
      setPhase("showingRecoveryKey");
    } catch (e) {
      console.error("Preparing vault failed", e);
      setError(e instanceof Error ? e.message : "Failed to create vault");
      setPhase("idle");
    } finally {
      setCreating(false);
    }
  };

  /**
   * The single irreversible step, run from the interstitial.
   *
   * By now the recovery file exists on the user's disk, which is the whole
   * reason the register call was deferred this long: a `vault` row must never
   * exist before the file that opens it does.
   *
   * On failure the prepared vault is deliberately KEPT, so pressing Continue
   * again re-registers the same vault id and the same recovery key — the PDF
   * already saved must stay valid.
   */
  const onConfirmRecoveryFile = async () => {
    if (!prepared) return;
    setCreating(true);
    setError(null);
    try {
      // A previous Continue may have got past the register call and then failed
      // during local setup. Re-registering would come back VAULT_EXISTS, so the
      // committed result is reused and only the local half is retried.
      if (committed) {
        await finishCreation(committed, connectDrive);
        return;
      }
      const result = await commitVaultRegistration(prepared, signupMutation.mutateAsync);
      setCommitted(result);
      await finishCreation(result, connectDrive);
    } catch (e) {
      console.error("Vault creation failed", e);
      setError(describeCommitError(e, { alreadyRegistered: committed !== null }));
    } finally {
      signupMutation.reset();
      setCreating(false);
    }
  };

  // The interstitial replaces the form entirely — there is no path back to it.
  if (prepared) {
    return (
      <RecoveryKeyInterstitial
        recoveryKey={prepared.recoveryKey}
        vaultId={prepared.vaultId}
        name={prepared.decryptedVault.name}
        busy={creating}
        error={error}
        onContinue={onConfirmRecoveryFile}
      />
    );
  }

  if (step === "name") {
    return (
      <VaultNameStep
        value={vaultName}
        onChange={setVaultName}
        onContinue={onCreate}
        onBack={() => {
          setError(null);
          setStep("password");
        }}
        busy={creating}
        error={error}
        submitLabel={connectDrive ? "Create & connect" : "Create vault"}
        title="Name your vault"
      />
    );
  }

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
        onPress={goToName}
        disabled={!canSubmit}
      >
        <Text className={`${canSubmit ? "text-primary-text" : "text-muted-text"} font-medium`}>
          {phase === "creatingLocal" ? "Creating vault…" : phase === "authorizing" ? "Authorizing…" : phase === "creatingRemote" ? "Creating provider file…" : phase === "verifying" ? "Verifying…" : "Continue"}
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
