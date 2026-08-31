import { useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";
import { useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/src/lib/state";
import { unlockWithPassword } from "@/src/lib/auth/flows";
import { teardownVaultSession } from "@/src/lib/auth/teardown";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { logout } from "@/src/lib/queries/logout/query";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";

/**
 * Lock screen: shown whenever the user is authenticated but the vault is
 * locked (keys wiped). Unlock re-derives the vault key locally from the
 * master password; logout tears the session down entirely.
 */
export default function Lock() {
  // Only valid in the "locked" state; anything else bounces to its canonical page.
  useAuthGuard(["locked"]);
  const router = useRouter();
  const queryClient = useQueryClient();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const session = useAppStore((s) => s.session);

  const onUnlock = async () => {
    setError(null);
    setSubmitting(true);
    try {
      await unlockWithPassword(password);
      // Reopen this account's per-user database (closed when the vault was
      // locked) so intents/sync can resume.
      if (session?.vaultId) await initSQLite(session.vaultId);
      setPassword("");
      router.replace("/home" as any);
    } catch (err) {
      console.warn("Unlock failed", err);
      setError(err instanceof Error ? err.message : "Failed to unlock.");
    } finally {
      setSubmitting(false);
    }
  };

  const onLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error("Logout failed", error);
    }
    // Same centralized teardown as the home-screen logout so pending intents
    // and device secrets can never leak across vaults.
    await teardownVaultSession(queryClient);
    router.replace("/" as any);
  };

  return (
    <View className="flex-1 items-center justify-center bg-black px-6">
      <Text className="text-white text-xl mb-1">Voult is locked</Text>
      <Text className="text-gray-400 text-sm mb-6">
        {session?.vaultId ? `Vault ${session.vaultId.slice(0, 8)}…` : ""}
      </Text>
      <TextInput
        className="w-full rounded-md bg-white px-3 py-2 mb-4"
        placeholder="Master password"
        placeholderTextColor="#666"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={onUnlock}
      />
      <Pressable
        className="w-full rounded-md bg-blue-600 py-2 items-center"
        onPress={onUnlock}
        disabled={submitting || !password}
      >
        <Text className="text-white">{submitting ? "Unlocking..." : "Unlock"}</Text>
      </Pressable>
      {error ? <Text className="text-red-400 mt-3">{error}</Text> : null}
      <Pressable className="mt-4" onPress={onLogout}>
        <Text className="text-red-400">Log out</Text>
      </Pressable>
    </View>
  );
}
