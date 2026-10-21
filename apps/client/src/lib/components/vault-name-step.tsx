import { Pressable, Text, TextInput, View } from "react-native";
import {
  DEFAULT_VAULT_NAME,
  MAX_VAULT_NAME_LENGTH,
  normalizeVaultName,
} from "@/src/lib/vault/name";

/**
 * Onboarding step 2: name the vault.
 *
 * Sits between the master password and the recovery file. The default is
 * pre-filled and selected, so "Continue" is always a valid decision — naming is
 * optional effort, not a gate. The name is validated here (and again when the
 * document is built) but is never uniqueness-checked: the UUID is the identity.
 *
 * Shared by both creation screens so the copy and the rules cannot drift.
 */
export function VaultNameStep({
  value,
  onChange,
  onContinue,
  onBack,
  busy,
  error,
  submitLabel = "Continue",
  title = "Name your vault",
  description = "This is what you will see in the app — on the lock screen, in the sidebar, and in your list of vaults. You can change it later in Settings.",
}: {
  value: string;
  onChange: (value: string) => void;
  onContinue: () => void;
  onBack: () => void;
  busy?: boolean;
  error?: string | null;
  submitLabel?: string;
  title?: string;
  description?: string;
}) {
  const normalized = normalizeVaultName(value);
  const tooLong = value.replace(/\s+/g, " ").trim().length > MAX_VAULT_NAME_LENGTH;
  const canContinue = normalized !== null && !busy;

  return (
    <View className="flex-1 justify-center bg-ground px-6">
      <Text className="text-primary-text text-xl mb-2">{title}</Text>
      <Text className="text-muted-text text-sm mb-6 leading-5">{description}</Text>

      <Text className="text-muted-text text-xs mb-2">Vault name</Text>
      <TextInput
        className="w-full rounded-md border border-border bg-surface px-3 py-2 mb-1 text-primary-text"
        placeholder={DEFAULT_VAULT_NAME}
        placeholderTextColor="#7E8590"
        value={value}
        onChangeText={onChange}
        autoFocus
        selectTextOnFocus
        autoCapitalize="words"
        autoCorrect={false}
        returnKeyType="next"
        onSubmitEditing={() => {
          if (canContinue) onContinue();
        }}
      />
      <Text className={`text-xs mb-4 ${tooLong ? "text-red-400" : "text-muted-text"}`}>
        {tooLong
          ? `Names can be up to ${MAX_VAULT_NAME_LENGTH} characters.`
          : `${normalized?.length ?? 0}/${MAX_VAULT_NAME_LENGTH}`}
      </Text>

      <Pressable
        accessibilityRole="button"
        className={`w-full rounded-md py-2 items-center ${
          canContinue ? "bg-accent-line" : "bg-surface border border-border"
        }`}
        onPress={onContinue}
        disabled={!canContinue}
      >
        <Text className={canContinue ? "text-primary-text font-medium" : "text-muted-text"}>
          {busy ? "Please wait…" : submitLabel}
        </Text>
      </Pressable>

      {error ? <Text className="text-red-400 mt-3 text-sm">{error}</Text> : null}

      <Pressable accessibilityRole="button" className="mt-4 items-center py-2" onPress={onBack} disabled={busy}>
        <Text className="text-muted-text text-xs">Back</Text>
      </Pressable>
    </View>
  );
}
