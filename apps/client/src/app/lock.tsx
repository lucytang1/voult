import { useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";
import { useAppStore, updateLockEpoch } from "@/src/lib/state";
import { unlockWithPassword, reauthenticateAndUnlock } from "@/src/lib/auth/flows";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { fetchSession } from "@/src/lib/queries/session/query";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { selectedVaultId } from "@/src/lib/state/vault-state";
import { displayVaultName } from "@/src/lib/vault/name";
import { Lock as LockIcon, AlertTriangle } from "lucide-react";

/**
 * Lock screen: the selected vault's keys are absent. Unlock re-derives the
 * vault key locally from the master password. There is no logout — states are
 * locked / unlocked or no vault selected.
 *
 * M2: this screen now serves two situations that used to be conflated as
 * "not authenticated":
 *
 *  - The cookie is fine, the keys are gone (ordinary lock). Unlock is a purely
 *    local unwrap; a wrong password fails here at AES-GCM and nothing about the
 *    attempt leaves the device.
 *  - The cookie is gone (expired / rejected). The vault is still selected, and
 *    the same password field re-establishes the session via the existing
 *    verifier flow before unwrapping. `serverSession` decides which path runs.
 *
 * A vault the server no longer knows about is an availability error, not a
 * fourth state: we stay locked, keep the selection, and offer switch/create.
 */
export default function Lock() {
  // Only valid in the "locked" state; anything else bounces to its canonical page.
  useAuthGuard(["locked"]);
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const vaultId = selectedVaultId(useAppStore((s) => s.vault));
  const serverSession = useAppStore((s) => s.serverSession);
  const availability = useAppStore((s) => s.availability);

  // A dead cookie means the password has to do double duty: re-authenticate,
  // then unwrap. With a live session it is a local unwrap only.
  const needsReauth = serverSession !== "active";
  const vaultUnavailable = availability === "unavailable";

  const onUnlock = async () => {
    if (!vaultId) return;
    setError(null);
    setSubmitting(true);
    try {
      if (needsReauth) {
        // Re-establishes the session with the existing verifier flow, then
        // unwraps locally. Sends only the verifier — never the password.
        await reauthenticateAndUnlock(password);
      } else {
        await unlockWithPassword(password);
      }

      // Reopen this vault's database (closed when it was locked) so
      // intents/sync can resume.
      await initSQLite(vaultId);
      // Converge to the current server epoch (a peer may have locked after
      // our lock metadata was captured). Best-effort: unlock stays valid.
      try {
        const remote = await fetchSession();
        updateLockEpoch(remote.lock_epoch ?? 0);
      } catch {
        // Offline — sync check converges later.
      }
      setPassword("");
      router.replace("/home" as any);
    } catch (err) {
      console.warn("Unlock failed", err);
      setError(err instanceof Error ? err.message : "Failed to unlock.");
    } finally {
      setSubmitting(false);
    }
  };

  const goToChooser = () => router.push("/vault" as any);
  const goToCreate = () => router.push("/vault/create" as any);

  // The server no longer has this vault. There is nothing to unlock into, so
  // the password form would only produce confusing errors — offer recovery.
  if (vaultUnavailable) {
    return (
      <View className="flex-1 items-center justify-center bg-ground px-6">
        <View className="w-12 h-12 rounded-full bg-card items-center justify-center mb-4 border border-border">
          <AlertTriangle size={22} color="#E0A458" />
        </View>
        <Text className="text-primary-text text-xl mb-1">Vault unavailable</Text>
        <Text className="text-muted-text text-sm mb-2 text-center">
          {vaultId ? `${displayVaultName(vaultId)} ` : ""}
          is no longer available on this server.
        </Text>
        <Text className="text-muted-text text-xs mb-6 text-center">
          Your selection has been kept. Switch to another vault or create a new
          one to continue.
        </Text>
        <Pressable
          className="w-full rounded-md bg-surface border border-border-strong py-2 items-center mb-2"
          onPress={goToChooser}
        >
          <Text className="text-primary-text">Switch vault</Text>
        </Pressable>
        <Pressable
          className="w-full rounded-md bg-surface border border-border py-2 items-center"
          onPress={goToCreate}
        >
          <Text className="text-primary-text">Create a new vault</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <View className="flex-1 items-center justify-center bg-ground px-6">
      <View className="w-12 h-12 rounded-full bg-card items-center justify-center mb-4 border border-border">
        <LockIcon size={22} color="#D89AC6" />
      </View>
      <Text className="text-primary-text text-xl mb-1">Voult is locked</Text>
      <Text className="text-muted-text text-sm mb-6">
        {vaultId ? displayVaultName(vaultId) : ""}
      </Text>

      {needsReauth ? (
        <Text className="text-muted-text text-xs mb-4 text-center">
          Your server session expired. Enter your master password to restore
          access to this vault.
        </Text>
      ) : null}

      <TextInput
        className="w-full rounded-md border border-border bg-surface px-3 py-2 mb-4 text-primary-text"
        placeholder="Master password"
        placeholderTextColor="#7E8590"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={onUnlock}
      />
      <Pressable
        className="w-full rounded-md bg-surface border border-border-strong py-2 items-center"
        onPress={onUnlock}
        disabled={submitting || !password}
      >
        <Text className="text-primary-text">
          {submitting ? "Unlocking..." : "Unlock"}
        </Text>
      </Pressable>
      {error ? <Text className="text-red-400 mt-3">{error}</Text> : null}

      <Pressable
        className="w-full rounded-md py-2 items-center mt-6"
        onPress={goToChooser}
      >
        <Text className="text-muted-text text-xs">Use a different vault</Text>
      </Pressable>

      {/* Case 3. The vault id travels with the link, which the bootstrap uses to
          route here; the recovery file itself supplies the vault it belongs to,
          so nothing has to be typed. */}
      <Pressable
        className="w-full rounded-md py-2 items-center mt-2"
        onPress={() => router.push(`/recover?recover=${vaultId ?? ""}` as any)}
      >
        <Text className="text-muted-text text-xs">
          Forgot your master password?
        </Text>
      </Pressable>
    </View>
  );
}