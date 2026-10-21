import { useState, type ReactNode } from "react";
import { ActivityIndicator, Pressable, Text, View } from "react-native";
import { useAppStore } from "@/src/lib/state";
import {
  useCloudBinding,
  useCloudCredentials,
  useCloudProviders,
  useCloudStatus,
  useDisconnectCloud,
  useMirrorCloudVault,
} from "@/src/lib/cloud/queries";
import { enableCloudForVault } from "@/src/lib/cloud/enableSync";
import {
  CloudProviderFallbackIcon,
  cloudProviderRegistry,
  providerLabelForKind,
} from "@/src/lib/cloud/providers";
import {
  BACKUP_TITLE_COLOR,
  describeBackup,
  describeBackupLoading,
  describeMirrorNetworkFailure,
  describeMirrorResult,
  type BackupView,
  type MirrorFeedback,
} from "@/src/lib/cloud/backup-status";
import type { CloudProviderInfo } from "@/src/lib/cloud/api";

/** A provider is "on" only when it is connected AND has an adopted remote file. */
function activeKindOf(connected: boolean, providerKind?: string, remoteFileId?: string): string | null {
  return connected && remoteFileId && providerKind ? providerKind : null;
}

interface ProviderRowProps {
  provider: CloudProviderInfo;
  /** Whether this row's switch reads as on. */
  on: boolean;
  /** True while this row's connect/switch is in flight. */
  busy: boolean;
  /** Any action is in flight, so every switch is disabled. */
  disabled: boolean;
  /** Credential detail line: account email when the provider is authorized. */
  subtitle: string;
  onToggle: (next: boolean) => void;
  /** Rendered inside the row, below the header, only while the row is on. */
  children?: ReactNode;
}

function ProviderToggle({
  on,
  disabled,
  label,
  onToggle,
}: {
  on: boolean;
  disabled: boolean;
  label: string;
  onToggle: (next: boolean) => void;
}) {
  return (
    <Pressable
      accessibilityRole="switch"
      accessibilityState={{ checked: on, disabled }}
      accessibilityLabel={label}
      disabled={disabled}
      onPress={() => onToggle(!on)}
      className={`h-6 w-11 flex-row items-center rounded-full border px-0.5 ${
        on ? "border-transparent bg-accent-line" : "border-hairline-accent bg-surface"
      } ${disabled ? "opacity-50" : ""}`}
      style={{ justifyContent: on ? "flex-end" : "flex-start" }}
    >
      <View
        className="h-5 w-5 rounded-full"
        style={{ backgroundColor: on ? "#F2F4F7" : "#7E8590" }}
      />
    </Pressable>
  );
}

function ProviderRow({ provider, on, busy, disabled, subtitle, onToggle, children }: ProviderRowProps) {
  const Icon = cloudProviderRegistry[provider.kind]?.icon ?? CloudProviderFallbackIcon;
  const label = providerLabelForKind(provider.kind);
  return (
    <View className="border-t-[0.1px] border-hairline py-5 first:border-t-0 first:pt-5 last:pb-5 px-5">
      <View className="flex-row items-center justify-between">
        <View className="flex-1 flex-row items-center pr-3">
          <Icon width={28} height={28} />
          <View className="ml-3 flex-1">
            <Text className="text-sm font-semibold text-primary-text">{label}</Text>
            <Text className="mt-0.5 text-xs text-muted-text">{subtitle}</Text>
          </View>
        </View>
        <View className="flex-row items-center gap-2">
          {busy && <ActivityIndicator size="small" color="#a1a1aa" />}
          <ProviderToggle
            on={on}
            disabled={disabled}
            label={`${on ? "Disconnect" : "Use"} ${label} for backup`}
            onToggle={onToggle}
          />
        </View>
      </View>
      {on && children && <View className="mt-3">{children}</View>}
    </View>
  );
}

export function ProviderSection() {
  const session = useAppStore((state) => state.session);
  const isLocked = useAppStore((state) => state.vault.status !== "unlocked");
  const enabled = !!session?.vaultId && !isLocked;

  const providersQuery = useCloudProviders();
  const statusQuery = useCloudStatus(session?.vaultId ?? "anonymous", enabled);
  const credentialsQuery = useCloudCredentials(enabled);
  const bindingQuery = useCloudBinding(session?.vaultId, enabled);
  const mirrorMutation = useMirrorCloudVault(session?.vaultId);
  const disconnectMutation = useDisconnectCloud();

  const status = statusQuery.data ?? null;
  const binding = bindingQuery.data ?? null;
  const activeKind = activeKindOf(!!status?.connected, binding?.provider_kind, binding?.remote_file_id);

  const [optimisticOn, setOptimisticOn] = useState<string | null>(null);
  const [busyKind, setBusyKind] = useState<string | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mirrorFeedback, setMirrorFeedback] = useState<MirrorFeedback | null>(null);

  const pending = busyKind !== null || disconnecting;
  const valueFor = (kind: string) => (pending ? kind === optimisticOn : kind === activeKind);

  const refresh = async () => {
    await Promise.all([
      statusQuery.refetch(),
      bindingQuery.refetch(),
      credentialsQuery.refetch(),
    ]);
  };

  const connect = async (kind: string) => {
    if (!session?.vaultId) return;
    setError(null);
    setBusyKind(kind);
    setOptimisticOn(kind);
    try {
      await enableCloudForVault(session.vaultId, kind);
      await refresh();
    } catch (e: any) {
      const message =
        e?.response?.data?.error_msg || e?.message || `Failed to connect ${providerLabelForKind(kind)}`;
      if (!message.includes("Redirecting")) setError(message);
    } finally {
      setBusyKind(null);
      setOptimisticOn(null);
    }
  };

  const disconnect = async () => {
    setError(null);
    setDisconnecting(true);
    setOptimisticOn(null);
    try {
      await disconnectMutation.mutateAsync();
      await refresh();
      setMirrorFeedback(null);
    } catch (e: any) {
      setError(e?.response?.data?.error_msg || e?.message || "Failed to disconnect");
    } finally {
      setDisconnecting(false);
      setOptimisticOn(null);
    }
  };

  const handleToggle = (kind: string, next: boolean) => {
    if (next) void connect(kind);
    else void disconnect();
  };

  const backupView: BackupView = binding?.remote_file_id ? describeBackup(binding) : describeBackupLoading();

  const handleBackupNow = async () => {
    setError(null);
    try {
      const { mirror } = await mirrorMutation.mutateAsync();
      setMirrorFeedback(describeMirrorResult(mirror));
    } catch (e: any) {
      setMirrorFeedback(describeMirrorNetworkFailure(e?.response?.data?.code));
    }
  };

  const providers = providersQuery.data ?? [];
  const configured = providersQuery.isSuccess ? providers.length > 0 : null;

  return (
    <View>
      <Text className="mb-6 text-2xl font-semibold text-primary-text">Providers</Text>

      <View className="rounded-2xl bg-surface1 overflow-hidden">
        {providersQuery.isPending ? (
          <View className="p-5">
            <Text className="text-sm text-muted-text">Loading providers…</Text>
          </View>
        ) : configured === false ? (
          <View className="p-5">
            <Text className="text-sm text-muted-text">Cloud backup is not configured on this server.</Text>
          </View>
        ) : (
          providers.map((provider) => {
            const credential = credentialsQuery.data?.find((item) => item.kind === provider.kind);
            const on = valueFor(provider.kind);
            const busy = busyKind === provider.kind || (disconnecting && provider.kind === activeKind);
            const showDetails = on && binding?.provider_kind === provider.kind;
            const subtitle = on
              ? "Backing up"
              : credential
                ? `Connected${credential.email ? ` · ${credential.email}` : ""}`
                : "Not connected";

            return (
              <ProviderRow
                key={provider.kind}
                provider={provider}
                on={on}
                busy={busy}
                disabled={pending}
                subtitle={subtitle}
                onToggle={(next) => handleToggle(provider.kind, next)}
              >
                {showDetails ? (
                  <View>
                    <View className="mb-2 flex-row items-center">
                      <View className={`mr-2 h-2 w-2 rounded-full ${backupView.dot}`} />
                      <Text className="text-sm font-medium" style={{ color: BACKUP_TITLE_COLOR[backupView.tone] }}>
                        {backupView.title}
                      </Text>
                    </View>
                    <Text className="text-sm text-muted-text">
                      {status?.email || `${providerLabelForKind(provider.kind)} account connected`}
                    </Text>
                    <Text className="mt-1 text-sm text-muted-text">{backupView.detail}</Text>
                    <Text className="mt-1 text-xs text-muted-text" numberOfLines={1}>
                      Remote file: {binding?.remote_file_id}
                    </Text>
                    {binding?.remote_revision && (
                      <Text className="mt-1 text-xs text-muted-text">
                        Provider revision: {binding.remote_revision.slice(0, 8)}
                      </Text>
                    )}

                    {mirrorFeedback && (
                      <Text className="mt-3 text-sm" style={{ color: BACKUP_TITLE_COLOR[mirrorFeedback.tone] }}>
                        {mirrorFeedback.text}
                      </Text>
                    )}

                    <Pressable
                      className="mt-4 self-start rounded-lg border border-hairline-accent bg-accent px-4 py-2"
                      onPress={handleBackupNow}
                      disabled={mirrorMutation.isPending || backupView.tone === "ok"}
                      accessibilityLabel={`Back up this vault to ${providerLabelForKind(provider.kind)} now`}
                    >
                      <Text className="text-sm text-primary-text">
                        {mirrorMutation.isPending ? "Backing up…" : "Back up now"}
                      </Text>
                    </Pressable>
                  </View>
                ) : null}
              </ProviderRow>
            );
          })
        )}

        {error && <Text className="mt-3 text-sm text-red-400 px-5">{error}</Text>}
      </View>
    </View>
  );
}