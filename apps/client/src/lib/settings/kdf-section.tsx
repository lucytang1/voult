import { useState } from "react";
import { ActivityIndicator, Pressable, Text, TextInput, View } from "react-native";
import { ShieldCheck } from "lucide-react";
import { useAppStore } from "@/src/lib/state";
import { useGetCryptoParams } from "@/src/lib/queries/cryptoParams/query";
import { describeKdf } from "@voult/vault-core";
import { upgradeVaultKdfWithPassword } from "@/src/lib/auth/kdf-upgrade";

/**
 * Settings > Security > Vault protection.
 *
 * The visible state is the vault's own KDF profile — the server stores it and
 * serves it, so there is nothing to cache locally. The upgrade action exists for
 * users who normally rely on the device key and therefore never type their
 * master password: without it, a vault created on a slow device would stay on a
 * lower rung forever.
 *
 * The password is used locally to unwrap the current envelope (which proves it),
 * then to derive and wrap the new credential. It never leaves the device.
 */
export function KdfSection() {
  const vaultId = useAppStore((s) => (s.vault.status === "no_vault" ? null : s.vault.vaultId));
  const unlocked = useAppStore((s) => s.vault.status === "unlocked");
  const params = useGetCryptoParams(vaultId ?? "", Boolean(vaultId) && unlocked);

  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!vaultId) return null;

  const reset = () => {
    setPassword("");
    setOpen(false);
    setBusy(false);
  };

  const upgrade = async () => {
    if (!password) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const outcome = await upgradeVaultKdfWithPassword(vaultId, password);
      setResult(
        outcome === "rotated"
          ? "Protection upgraded. Your master password is unchanged."
          : outcome === "already"
            ? "This vault was already upgraded by another tab or device."
            : "This vault is already at (or above) the strongest profile this device can run.",
      );
      setPassword("");
      setOpen(false);
    } catch (e) {
      const message = (e as Error)?.message;
      setError(
        message === "Incorrect password."
          ? "That is not this vault's master password — or its protection changed in another tab. Reload and try again."
          : message === "KDF_UPGRADE_VERIFY_FAILED"
            ? "The new protection could not be verified locally, so nothing was changed."
            : "The upgrade did not finish. Nothing was changed — try again.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <View className="mt-6 mb-4 overflow-hidden rounded-2xl bg-surface1 p-5">
      <View className="mb-2 flex-row items-center gap-2">
        <ShieldCheck size={16} strokeWidth={1.75} className="text-muted-text" />
        <Text className="text-sm font-semibold text-primary-text">Vault protection</Text>
      </View>

      <Text className="mb-1 text-xs text-muted-text">
        Your master password is stretched with Argon2id before it becomes a key.
        A stronger profile makes offline guessing more expensive.
      </Text>
      <Text className="mb-3 text-xs text-primary-text">
        {params.data ? describeKdf(params.data.kdf) : "Reading profile…"}
      </Text>

      {result ? <Text className="mb-3 text-xs text-emerald-400">{result}</Text> : null}
      {error ? <Text className="mb-3 text-xs text-red-400">{error}</Text> : null}

      {open ? (
        <View>
          <Text className="mb-2 text-xs text-muted-text">
            Enter your master password to rewrap this vault's key at the
            strongest profile this device can run. It is used on this device only.
          </Text>
          <TextInput
            value={password}
            onChangeText={setPassword}
            placeholder="Master password"
            placeholderTextColor="#71717a"
            secureTextEntry
            autoComplete="current-password"
            className="mb-3 rounded-lg border border-hairline-accent bg-ground px-3 py-2.5 text-sm text-primary-text"
            onSubmitEditing={upgrade}
          />
          <View className="flex-row gap-2">
            <Pressable
              className="rounded-lg border border-hairline-accent bg-surface px-4 py-2.5"
              onPress={reset}
              disabled={busy}
            >
              <Text className="text-sm text-primary-text">Cancel</Text>
            </Pressable>
            <Pressable
              className="flex-row items-center gap-2 rounded-lg bg-accent border border-hairline-accent px-4 py-2.5"
              onPress={upgrade}
              disabled={busy || !password}
            >
              {busy ? <ActivityIndicator size="small" color="#fafafa" /> : null}
              <Text className="text-sm text-primary-text">
                {busy ? "Upgrading…" : "Upgrade protection"}
              </Text>
            </Pressable>
          </View>
        </View>
      ) : (
        <Pressable
          className="self-start rounded-lg bg-accent border border-hairline-accent px-4 py-2.5"
          onPress={() => {
            setResult(null);
            setError(null);
            setOpen(true);
          }}
        >
          <Text className="text-sm text-primary-text">Upgrade protection</Text>
        </Pressable>
      )}
    </View>
  );
}
