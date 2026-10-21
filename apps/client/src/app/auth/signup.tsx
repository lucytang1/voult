import { Link, useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, Text, View } from "react-native";
import { TextField } from "@/src/lib/components/text-field";
import { prepareVaultFlow, type CreateVaultResult } from "@/src/lib/vault/create";
import { commitVaultRegistration, describeCommitError, type PendingVaultRegistration } from "@/src/lib/vault/registration";
import { persistDeviceSecrets } from "@/src/lib/auth/utils";
import { RecoveryKeyInterstitial } from "@/src/lib/components/recovery-key-interstitial";
import { VaultNameStep } from "@/src/lib/components/vault-name-step";
import { DEFAULT_VAULT_NAME } from "@/src/lib/vault/name";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { upsertVaultId, upsertVaultVersion } from "@/src/lib/sqlite/web/services/client-state-service";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { useSignUp } from "@/src/lib/queries/SignUp/query";
import {
  selectVaultSession,
  commitVaultUnlock,
  updateDecryptedVault,
  updateLockEpoch,
  updateVaultVersion,
} from "../../lib/state";


export default function SignUp() {
  // Signup is only for signed-out users; authenticated users are bounced
  // to /lock (locked) or /home (unlocked).
  useAuthGuard(["no_vault"]);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // Onboarding is deliberately two steps: pick a name (pre-filled) after the
  // password, before the recovery file. Naming is never a gate on creation.
  const [step, setStep] = useState<"password" | "name">("password");
  const [vaultName, setVaultName] = useState(DEFAULT_VAULT_NAME);
  const router = useRouter();
  const signupMutation = useSignUp();
  // The vault exists only in memory until the user saves the recovery file and
// presses Continue; this is what the interstitial renders.
const [prepared, setPrepared] = useState<PendingVaultRegistration | null>(null);
  // Set the moment /register succeeds, so a retry after a local-setup failure
  // does not register a second time.
  const [committed, setCommitted] = useState<CreateVaultResult | null>(null);

  const onSubmit = () => {
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Master password must be at least 8 characters.");
      return;
    }
    setError(null);
    setStep("name");
  };

  /**
   * Step 2. Everything here is still local: the vault id, key and envelopes are
   * derived after the name is chosen, and nothing is sent to the server until
   * the recovery file has been saved and Continue pressed on the interstitial.
   */
  const onPrepare = async () => {
    setError(null);
    setSubmitting(true);
    try {
      // Local preparation only — the vault id is generated here on this device,
      // no email is ever collected, and nothing is sent to the server. The
      // server hears about this vault only after the user has the recovery
      // file, so a reload on the interstitial cannot leave a vault behind whose
      // recovery path is dead.
      // A new vault is created EMPTY: no demo entries, no seeded credentials.
      // Everything the vault holds is something the user added themselves.
      const prepared = await prepareVaultFlow(password, vaultName);
      setPrepared(prepared);
    } catch (err) {
      console.error("Vault preparation failed", err);
      setError(err instanceof Error ? err.message : "Sign up failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const onConfirmRecoveryFile = async () => {
    if (!prepared) return;
    setSubmitting(true);
    setError(null);
    try {
      // A previous Continue may have got past the register call and then failed
      // during local setup. Re-registering would come back VAULT_EXISTS, so the
      // committed result is reused and only the local half is retried.
      if (committed) {
        await finish(committed);
        return;
      }
      // The single irreversible step, and the only network call in creation.
      const result = await commitVaultRegistration(prepared, signupMutation.mutateAsync);
      setCommitted(result);
      await finish(result);
    } catch (err) {
      // The prepared vault is kept so a retry re-registers the SAME vault id and
      // recovery key — the file the user just saved must not be orphaned by a
      // flaky network.
      console.error("Vault creation failed", err);
      setError(describeCommitError(err, { alreadyRegistered: committed !== null }));
    } finally {
      signupMutation.reset();
      setSubmitting(false);
    }
  };

  /**
   * Runs only after the vault is registered and the user has the recovery file.
   * The device key is enrolled here, never before, so no vault ends up with a
   * working device key but an unsaved recovery file.
   */
  const finish = async (result: CreateVaultResult) => {
    try {
      const vaultId = result.session.vaultId;
      await persistDeviceSecrets(result.vaultKeyRaw, vaultId);
      // Select before installing the key: a newly created vault has no
      // prior selection, and commitVaultUnlock needs one to install against.
      selectVaultSession(result.session);
      commitVaultUnlock(result.vaultKey);
      updateLockEpoch(result.lockEpoch);
      updateDecryptedVault(result.decryptedVault);
      updateVaultVersion(result.version);
      await initSQLite(vaultId);
      await upsertVaultId(vaultId);
      await upsertVaultVersion(result.version);
      result.vaultKeyRaw.fill(0);
      setPrepared(null);
      router.replace("/home" as any);
    } catch (err) {
      console.error("Failed to finish vault creation", err);
      setError(err instanceof Error ? err.message : "Failed to finish vault creation.");
    }
  };

  if (prepared) {
    return (
      <RecoveryKeyInterstitial
        recoveryKey={prepared.recoveryKey}
        vaultId={prepared.vaultId}
        name={prepared.decryptedVault.name}
        busy={submitting}
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
        onContinue={onPrepare}
        onBack={() => {
          setError(null);
          setStep("password");
        }}
        busy={submitting}
        error={error}
        submitLabel="Continue"
      />
    );
  }

  return (
    <View className="flex-1 items-center justify-center bg-ground px-6">
      <Text className="text-primary-text text-xl mb-4">Create new vault</Text>
      <Text className="text-muted-text text-xs mb-6">
        Your vault id is generated on this device. No email is required.
      </Text>
      <TextField
        className="mb-3"
        placeholder="Master password (≥8 chars)"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
      />
      <TextField
        className="mb-4"
        placeholder="Confirm password"
        secureTextEntry
        value={confirm}
        onChangeText={setConfirm}
      />
      <Pressable
        className="w-full rounded-md bg-surface border border-border-strong py-2 items-center"
        onPress={onSubmit}
        disabled={submitting || !password || !confirm}
      >
        <Text className="text-primary-text">Continue</Text>
      </Pressable>
      {error ? <Text className="text-red-400 mt-3">{error}</Text> : null}

      <Link href="/" asChild>
        <Pressable className="mt-4">
          <Text className="text-accent-text">Back</Text>
        </Pressable>
      </Link>
      <Text className="text-muted-text text-xs mt-4 text-center">
        Already have a Drive backup? Go back and use "Continue with Google Drive" to restore it — no vault id needed.
      </Text>
    </View>
  );
}
