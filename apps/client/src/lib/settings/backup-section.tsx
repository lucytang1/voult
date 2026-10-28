import { useEffect, useState, type ReactNode } from "react";
import { ActivityIndicator, Pressable, Text, View } from "react-native";
import { useAppStore } from "@/src/lib/state";
import {
  useCloudBinding,
  useCloudCredentials,
  useCloudProviders,
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
  BACKUP_DOT,
  BACKUP_TONE_COLOR,
  describeBackup,
  describeMirrorNetworkFailure,
  describeMirrorResult,
  isBackupInFlight,
  technicalDetails,
  type BackupAction,
  type BackupView,
  type MirrorFeedback,
} from "@/src/lib/cloud/backup-view";
import { Collapsible } from "@/src/lib/components/collapsible";
import type { CloudBinding, CloudProviderInfo } from "@/src/lib/cloud/api";

/**
 * Backup settings: which provider holds the disaster-recovery copy, and whether
 * that copy is actually current.
 *
 * Three rules, all of them reactions to the previous version of this screen:
 *
 *  1. **One active provider.** `cloud_binding` is keyed by vault id, so the
 *     product model is "one provider per vault". Rows are a radio group, not
 *     independent switches — a switch that turned another row off read as a bug.
 *  2. **Say only what the server confirmed.** The status line comes from
 *     `describeBackup`, which is derived from `cloud_binding`; the numbers live
 *     behind "Technical details".
 *  3. **Actions always do something.** "Back up now" is never disabled for being
 *     current — it verifies the remote copy and re-uploads. Switching is refused
 *     while a backup is in flight, because the server refuses it too, and the
 *     reason is shown instead of a dead control.
 */
export function BackupSection() {
  const session = useAppStore((state) => state.session);
  const isLocked = useAppStore((state) => state.vault.status !== "unlocked");
  const vaultId = session?.vaultId;
  const enabled = !!vaultId && !isLocked;

  const providersQuery = useCloudProviders();
  const credentialsQuery = useCloudCredentials(enabled);
  const mirrorMutation = useMirrorCloudVault(vaultId);
  const disconnectMutation = useDisconnectCloud();

  // Pin the binding poll to a fast cadence for the duration of anything this
  // pane started, so the status line cannot lag behind a switch or a manual
  // backup by more than a tick.
  const localActionInFlight = mirrorMutation.isPending || disconnectMutation.isPending;
  const bindingQuery = useCloudBinding(vaultId, {
    enabled,
    fast: localActionInFlight,
  });

  const [busyKind, setBusyKind] = useState<string | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  const [confirmReplace, setConfirmReplace] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mirrorFeedback, setMirrorFeedback] = useState<MirrorFeedback | null>(null);
  // Session-only note: the copy at the provider we just left is still on disk
  // and will never be updated again. Saying so once beats leaving the user to
  // discover two diverging backup files later.
  const [switchedFrom, setSwitchedFrom] = useState<string | null>(null);

  // One slow tick drives both "2 minutes ago" and the transition to "still
  // backing up…". Nothing here needs sub-second precision.
  const now = useNow(5_000);

  const binding = bindingQuery.data ?? null;
  const activeKind = binding?.provider_kind ?? null;
  const credentials = credentialsQuery.data ?? [];
  const hasCredential = !!binding && credentials.some((item) => item.kind === binding.provider_kind);
  const loading = bindingQuery.isPending || (enabled && credentialsQuery.isPending);
  const inFlight = isBackupInFlight(binding);

  const view: BackupView = describeBackup({
    binding: bindingQuery.isPending ? undefined : binding,
    hasCredential,
    providerKind: binding?.provider_kind,
    loading,
    localSaving: mirrorMutation.isPending,
    now,
  });

  const switching = busyKind !== null;
  const pending = switching || disconnecting || mirrorMutation.isPending;
  // The server rejects a switch while a mirror holds the vault; refusing here
  // first keeps the reason visible instead of returning a 409 after a wait.
  const switchBlocked = inFlight || pending;
  // Without a vault id there is nothing to bind a provider to, so leave the
  // controls inert rather than no-oping on press.
  const canSwitch = !!vaultId && !switchBlocked;

  const refresh = async () => {
    await Promise.all([bindingQuery.refetch(), credentialsQuery.refetch()]);
  };

  const switchTo = async (kind: string) => {
    if (!vaultId) return;
    setError(null);
    setMirrorFeedback(null);
    setConfirmReplace(false);
    setBusyKind(kind);
    try {
      const previous = activeKind;
      // Flushes pending intents, reuses a retained credential, and on the server
      // creates/repairs the provider file under the mirror claim.
      await enableCloudForVault(vaultId, kind);
      await refresh();
      if (previous && previous !== kind) setSwitchedFrom(previous);
    } catch (e: any) {
      const code = e?.response?.data?.code;
      const message =
        e?.response?.data?.error_msg || e?.message || `Failed to connect ${providerLabelForKind(kind)}`;
      if (code === "BACKUP_IN_PROGRESS") {
        setError("A backup is still finishing. Try again in a moment.");
        await refresh();
      } else if (!message.includes("Redirecting")) {
        // "Redirecting…" is the OAuth flow navigating away, not an error.
        setError(message);
      }
    } finally {
      setBusyKind(null);
    }
  };

  const backupNow = async () => {
    setError(null);
    try {
      const { mirror } = await mirrorMutation.mutateAsync();
      setMirrorFeedback(describeMirrorResult(mirror, binding?.provider_kind));
      await refresh();
    } catch {
      setMirrorFeedback(describeMirrorNetworkFailure());
    }
  };

  const disconnect = async () => {
    setError(null);
    setDisconnecting(true);
    setConfirmReplace(false);
    try {
      await disconnectMutation.mutateAsync();
      await refresh();
      setConfirmDisconnect(false);
      setMirrorFeedback(null);
      setSwitchedFrom(null);
    } catch (e: any) {
      setError(e?.response?.data?.error_msg || e?.message || "Failed to disconnect");
    } finally {
      setDisconnecting(false);
    }
  };

  const runAction = (action: BackupAction) => {
    if (action === "backup-now" || action === "retry") void backupNow();
    else if (activeKind) void switchTo(activeKind);
  };

  const providers = providersQuery.data ?? [];
  const configured = providersQuery.isSuccess ? providers.length > 0 : null;

  return (
    <View>
      <View className="rounded-2xl bg-surface1 overflow-hidden">
        {providersQuery.isPending ? (
          <View className="p-5">
            <Text className="text-sm text-muted-text">Loading providers…</Text>
          </View>
        ) : configured === false ? (
          <View className="p-5">
            <Text className="text-sm text-muted-text">
              Cloud backup is not configured on this server.
            </Text>
          </View>
        ) : (
          providers.map((provider) => {
            const isActive = provider.kind === activeKind;
            const credential = credentials.find((item) => item.kind === provider.kind);
            const isBusy = busyKind === provider.kind;
            const showStatus = isActive && view.phase !== "none";

            return (
              <ProviderRow
                key={provider.kind}
                provider={provider}
                subtitle={subtitleFor(provider.kind, isActive, credential?.email)}
                trailing={
                  isBusy ? (
                    <View className="flex-row items-center">
                      <ActivityIndicator size="small" color="#a1a1aa" />
                      <Text className="ml-2 text-xs text-muted-text">Switching…</Text>
                    </View>
                  ) : isActive ? (
                    <View className="flex-row items-center">
                      <View className="mr-2 h-2 w-2 rounded-full bg-accent-line" />
                      <Text className="text-xs font-medium text-primary-text">Active</Text>
                    </View>
                  ) : (
                    <Pressable
                      accessibilityRole="button"
                      accessibilityLabel={`Use ${providerLabelForKind(provider.kind)} for backup`}
                      accessibilityState={{ disabled: !canSwitch }}
                      disabled={!canSwitch}
                      onPress={() => void switchTo(provider.kind)}
                      className={`rounded-lg border border-hairline-accent bg-surface px-3 py-1.5 ${
                        canSwitch ? "" : "opacity-40"
                      }`}
                    >
                      <Text className="text-xs text-primary-text">
                        {credential ? "Use for backup" : "Connect"}
                      </Text>
                    </Pressable>
                  )
                }
              >
                {showStatus && (
                  <View className="mt-4">
                    <StatusLine view={view} />
                    {switchedFrom && switchedFrom !== provider.kind && (
                      <Text className="mt-2 text-xs text-muted-text">
                        The copy in {providerLabelForKind(switchedFrom)} is no longer updated.
                      </Text>
                    )}
                    {mirrorFeedback && (
                      <Text
                        className="mt-3 text-sm"
                        style={{ color: BACKUP_TONE_COLOR[mirrorFeedback.tone] }}
                      >
                        {mirrorFeedback.text}
                      </Text>
                    )}

                    <View className="mt-4 flex-row items-center gap-2">
                      {view.action && (
                        <ActionButton
                          action={view.action}
                          busy={mirrorMutation.isPending}
                          onPress={() => {
                            if (view.action === "replace") setConfirmReplace(true);
                            else runAction(view.action as BackupAction);
                          }}
                        />
                      )}
                      {/* Nothing to disconnect while paused: the credential is
                          already gone, and the only useful move is Reconnect. */}
                      {view.phase !== "paused" &&
                        (confirmDisconnect ? (
                          <>
                            <Pressable
                              className="rounded-lg border border-hairline-accent px-4 py-2"
                              onPress={() => setConfirmDisconnect(false)}
                              disabled={disconnecting}
                            >
                              <Text className="text-sm text-primary-text">Cancel</Text>
                            </Pressable>
                            <Pressable
                              className="rounded-lg border border-hairline-accent px-4 py-2"
                              onPress={() => void disconnect()}
                              disabled={disconnecting}
                            >
                              <Text className="text-sm text-red-400">
                                {disconnecting ? "Disconnecting…" : "Stop backups"}
                              </Text>
                            </Pressable>
                          </>
                        ) : (
                          <Pressable
                            accessibilityRole="button"
                            accessibilityLabel={`Stop backing up to ${providerLabelForKind(provider.kind)}`}
                            className="rounded-lg px-3 py-2"
                            onPress={() => setConfirmDisconnect(true)}
                            disabled={pending}
                          >
                            <Text className="text-sm text-muted-text">Disconnect</Text>
                          </Pressable>
                        ))}
                    </View>

                    {/* Replacing a diverged cloud copy is destructive and can
                        only be authorised by the person who owns both copies,
                        so it takes a second, explicit click. */}
                    {confirmReplace && (
                      <View className="mt-2">
                        <Text className="text-xs text-red-400">
                          The copy in {providerLabelForKind(provider.kind)} will be overwritten by
                          this vault's copy. The copy currently there cannot be recovered.
                        </Text>
                        <View className="mt-2 flex-row items-center gap-2">
                          <Pressable
                            className="rounded-lg border border-hairline-accent px-3 py-1.5"
                            onPress={() => setConfirmReplace(false)}
                          >
                            <Text className="text-xs text-primary-text">Cancel</Text>
                          </Pressable>
                          <Pressable
                            className={`rounded-lg border border-hairline-accent px-3 py-1.5 ${
                              busyKind ? "opacity-50" : ""
                            }`}
                            disabled={busyKind !== null}
                            onPress={() => {
                              setConfirmReplace(false);
                              if (activeKind) void switchTo(activeKind);
                            }}
                          >
                            <Text className="text-xs text-red-400">Replace it</Text>
                          </Pressable>
                        </View>
                      </View>
                    )}

                    {confirmDisconnect && (
                      <Text className="mt-2 text-xs text-muted-text">
                        Voult forgets this provider's access. The copy already in{" "}
                        {providerLabelForKind(provider.kind)} is left as it is.
                      </Text>
                    )}

                    <TechnicalDetails binding={binding} />
                  </View>
                )}
              </ProviderRow>
            );
          })
        )}

        {error && <Text className="mt-3 px-5 pb-5 text-sm text-red-400">{error}</Text>}

        {bindingQuery.isError && !error && (
          <Text className="mt-3 px-5 pb-5 text-sm text-muted-text">
            Could not read the backup status from the server.
          </Text>
        )}
      </View>

      {/* Switching is refused while a backup runs, so say why rather than
          leaving a disabled control to be guessed at. */}
      {switchBlocked && !pending && providers.length > 1 && (
        <Text className="mt-3 px-1 text-xs text-muted-text">
          Waiting for the current backup to finish before you can switch providers.
        </Text>
      )}
    </View>
  );
}

/** Re-renders on an interval so relative times and the stalled threshold move. */
function useNow(intervalMs: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

function subtitleFor(kind: string, isActive: boolean, email: string | undefined): string {
  if (isActive) return email ? `Active · ${email}` : "Active";
  if (email) return `Connected · ${email}`;
  return "Not connected";
}

function StatusLine({ view }: { view: BackupView }) {
  return (
    <View>
      <View className="flex-row items-center">
        <View className={`mr-2 h-2 w-2 rounded-full ${BACKUP_DOT[view.tone]}`} />
        <Text
          className="text-sm font-medium"
          style={{ color: BACKUP_TONE_COLOR[view.tone] }}
        >
          {view.headline}
        </Text>
        {view.phase === "saving" && (
          <ActivityIndicator size="small" color="#a1a1aa" style={{ marginLeft: 8 }} />
        )}
      </View>
      {!!view.detail && <Text className="mt-1 text-sm text-muted-text">{view.detail}</Text>}
    </View>
  );
}

const ACTION_LABEL: Record<BackupAction, string> = {
  "backup-now": "Back up now",
  retry: "Try again",
  reconnect: "Reconnect",
  recreate: "Start a new backup",
  replace: "Replace the cloud copy",
};

function ActionButton({
  action,
  busy,
  onPress,
}: {
  action: BackupAction;
  busy: boolean;
  onPress: () => void;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={ACTION_LABEL[action]}
      accessibilityState={{ disabled: busy }}
      disabled={busy}
      onPress={onPress}
      className={`rounded-lg border border-hairline-accent bg-accent px-4 py-2 ${
        busy ? "opacity-50" : ""
      }`}
    >
      <Text className="text-sm text-primary-text">
        {busy && (action === "backup-now" || action === "retry") ? "Backing up…" : ACTION_LABEL[action]}
      </Text>
    </Pressable>
  );
}

/**
 * The numbers, collapsed.
 *
 * Everything here is real state from `cloud_binding`; none of it belongs in the
 * primary line, because none of it changes what a user would do.
 */
function TechnicalDetails({ binding }: { binding: CloudBinding | null }) {
  const rows = technicalDetails(binding);
  if (rows.length === 0) return null;
  return (
    <View className="mt-4">
      <Collapsible title="Additional details">
        <View className="rounded-lg bg-surface2 px-3 py-2">
          {rows.map((row) => (
            <View key={row.label} className="flex-row justify-between py-1">
              <Text className="pr-4 text-xs text-muted-text">{row.label}</Text>
              <Text className="flex-1 text-right text-xs text-muted-text" numberOfLines={1}>
                {row.value}
              </Text>
            </View>
          ))}
        </View>
      </Collapsible>
    </View>
  );
}

function ProviderRow({
  provider,
  subtitle,
  trailing,
  children,
}: {
  provider: CloudProviderInfo;
  subtitle: string;
  trailing: ReactNode;
  children?: ReactNode;
}) {
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
        <View className="flex-row items-center gap-2">{trailing}</View>
      </View>
      {children}
    </View>
  );
}
