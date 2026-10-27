import { useState } from "react";
import { Pressable, Text, View } from "react-native";
import { useRouter } from "expo-router";
import { useAppStore } from "@/src/lib/state";
import { signOutOfVault } from "@/src/lib/auth/teardown";
import { queryClient } from "@/src/lib/queries/client";

/**
 * M2: control over this device's local unlock material.
 *
 * Session loss keeps the device key and envelope so an expired cookie doesn't
 * downgrade the vault into a full password re-entry every time. That retention
 * is a usability trade with a security cost — the material persists on this
 * device after the server session is gone — so the user needs a way to revoke
 * it. This is that control, and it is deliberately explicit and two-step.
 *
 * Revoking is irreversible without the master password: the next unlock of this
 * vault has to go through the password flow. That is the point, but it means
 * it should never be one stray tap, hence the confirm step.
 */
export function DeviceUnlockSection() {
  const router = useRouter();
  const vaultId = useAppStore((s) => (s.vault.status === "no_vault" ? null : s.vault.vaultId));
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!vaultId) return null;

  const revoke = async () => {
    setBusy(true);
    try {
      await signOutOfVault(queryClient, vaultId);
      setConfirming(false);
      // Back to the landing page: there is no longer a selection to restore.
      router.replace("/" as any);
    } finally {
      setBusy(false);
    }
  };

  return (
    <View className="mt-6 mb-4 rounded-2xl bg-surface1 overflow-hidden p-5">
      <Text className="mb-2 text-sm font-semibold text-primary-text">
        Unlock this device automatically
      </Text>
      <Text className="mb-3 text-xs text-muted-text">
        Voult keeps a device key on this browser so you can unlock without
        retyping your master password — including after a server session
        expires. Revoking it removes that key from this device only. Your vault
        and any other device are unaffected.
      </Text>

      {confirming ? (
        <View>
          <Text className="mb-3 text-xs text-red-400">
            You will need your master password to unlock this vault on this
            device again.
          </Text>
          <View className="flex-row gap-2">
            <Pressable
              className="rounded-lg bg-surface border border-hairline-accent px-4 py-2.5"
              onPress={() => setConfirming(false)}
              disabled={busy}
            >
              <Text className="text-sm text-primary-text">Cancel</Text>
            </Pressable>
            <Pressable
              className="rounded-lg border border-hairline-accent px-4 py-2.5"
              onPress={revoke}
              disabled={busy}
            >
              <Text className="text-sm text-red-400">
                {busy ? "Revoking…" : "Revoke device key"}
              </Text>
            </Pressable>
          </View>
        </View>
      ) : (
        <Pressable
          className="self-start rounded-lg bg-accent border border-hairline-accent px-4 py-2.5"
          onPress={() => setConfirming(true)}
        >
          <Text className="text-sm text-primary-text">Forget this device</Text>
        </Pressable>
      )}
    </View>
  );
}