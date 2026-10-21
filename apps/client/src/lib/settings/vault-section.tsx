import { useEffect, useState } from "react";
import { Pressable, Text, View } from "react-native";
import { TextField } from "../components/text-field";
import { useAppStore } from "../state";
import { selectedVaultId } from "../state/vault-state";
import { renameVault } from "../vault/rename";
import { MAX_VAULT_NAME_LENGTH, normalizeVaultName } from "../vault/name";

/**
 * Settings > Vault.
 *
 * Renaming is available only while unlocked (the Settings route is gated on
 * that), because the name lives inside the encrypted document and the rename
 * has to be encrypted with the vault key. The raw UUID is kept here, with a
 * copy action: it is still what identifies the vault to recovery, storage and
 * the server, but it no longer has to be the label anywhere user-facing.
 */
export function VaultSection() {
  const vaultId = useAppStore((s) => selectedVaultId(s.vault));
  const currentName = useAppStore((s) => s.decryptedVault?.name ?? "");
  const [name, setName] = useState(currentName);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  // An unlock, a sync or a switch can change the canonical name underneath us.
  useEffect(() => {
    setName(currentName);
  }, [currentName]);

  const normalized = normalizeVaultName(name);
  const tooLong = name.replace(/\s+/g, " ").trim().length > MAX_VAULT_NAME_LENGTH;
  const dirty = normalized !== null && normalized !== currentName;

  const onSave = async () => {
    if (!normalized) {
      setError("Enter a name between 1 and 48 characters.");
      return;
    }
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await renameVault(normalized);
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not rename this vault.");
    } finally {
      setBusy(false);
    }
  };

  const onCopyId = async () => {
    if (!vaultId) return;
    try {
      await navigator.clipboard.writeText(vaultId);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Could not copy the vault id — select it and copy manually.");
    }
  };

  return (
    <View className="rounded-2xl bg-surface1 overflow-hidden p-5">
      <Text className="mb-1 text-sm font-semibold text-primary-text">Vault name</Text>
      <Text className="text-sm text-muted-text">
        Shown on the lock screen, in the sidebar and in the vault chooser. It is stored
        inside your encrypted vault, so this server never sees it.
      </Text>

      <View className="mt-4">
        <TextField
          placeholder="Vault name"
          value={name}
          onChangeText={(next) => {
            setName(next);
            setSaved(false);
            setError(null);
          }}
          onSubmitEditing={onSave}
          autoCapitalize="words"
          autoCorrect={false}
          maxLength={MAX_VAULT_NAME_LENGTH * 2}
        />
        <View className="mt-1 flex-row items-center">
          <Text className={`text-xs ${tooLong ? "text-red-400" : "text-muted-text"}`}>
            {tooLong
              ? `Names can be up to ${MAX_VAULT_NAME_LENGTH} characters.`
              : `${normalized?.length ?? 0}/${MAX_VAULT_NAME_LENGTH}`}
          </Text>
          {saved ? <Text className="ml-3 text-xs text-accent-text">Saved</Text> : null}
        </View>

        <Pressable
          accessibilityRole="button"
          className={`mt-3 self-start rounded-lg px-4 py-2 ${
            dirty && !busy ? "bg-accent-line" : "bg-surface border border-border"
          }`}
          onPress={onSave}
          disabled={!dirty || busy}
        >
          <Text className={dirty && !busy ? "text-primary-text font-medium" : "text-muted-text"}>
            {busy ? "Saving…" : "Save name"}
          </Text>
        </Pressable>
      </View>

      {error ? <Text className="mt-3 text-xs text-red-400">{error}</Text> : null}

      <View className="mt-6 border-t-[0.1px] border-hairline pt-5">
        <Text className="mb-1 text-sm font-semibold text-primary-text">Vault ID</Text>
        <Text className="text-sm text-muted-text">
          The permanent identifier for this vault. It is what a recovery file and the server
          use; it cannot be changed.
        </Text>
        <View className="mt-3 flex-row items-center gap-3">
          <Text selectable className="flex-1 text-xs text-primary-text" style={{ fontFamily: "monospace" }}>
            {vaultId ?? "—"}
          </Text>
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Copy vault id"
            className="rounded-lg border border-border bg-surface px-3 py-1.5"
            onPress={onCopyId}
            disabled={!vaultId}
          >
            <Text className="text-xs text-muted-text">{copied ? "Copied" : "Copy"}</Text>
          </Pressable>
        </View>
      </View>
    </View>
  );
}
