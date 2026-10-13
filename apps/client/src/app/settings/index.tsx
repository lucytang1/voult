import { useState } from "react";
import { Pressable, ScrollView, Text, View } from "react-native";
import { useRouter } from "expo-router";
import { ArrowLeft, Cloud, Puzzle, Shield, type LucideIcon } from "lucide-react";
import { useAppStore } from "@/src/lib/state";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { ExtensionPairing } from "@/src/lib/extension-pair";
import { AutolockSection } from "@/src/lib/settings/autolock-section";
import { DeviceUnlockSection } from "@/src/lib/settings/device-unlock-section";
import {
  useDisconnectCloud,
  useCloudBinding,
  useCloudCredentials,
  useCloudProviders,
  useCloudStatus,
  useMirrorCloudVault,
} from "@/src/lib/cloud/queries";
import { enableCloudForVault } from "@/src/lib/cloud/enableSync";
import { providerLabelForKind } from "@/src/lib/cloud/providers";
import {
  BACKUP_TITLE_COLOR,
  describeBackup,
  describeBackupLoading,
  describeMirrorNetworkFailure,
  describeMirrorResult,
  type BackupView,
  type MirrorFeedback,
} from "@/src/lib/cloud/backup-status";

// The left rail, the page header and the content pane all read from this one
// map, so adding a section is a single entry rather than three parallel edits.
const SECTIONS: Record<string, { label: string; title: string; description: string; icon: LucideIcon }> = {
  extension: {
    label: "Extension",
    title: "Extension",
    description: "Connect Voult to your browser extension.",
    icon: Puzzle,
  },
  provider: {
    label: "Provider",
    title: "Provider",
    description: "Keep an encrypted backup with your cloud provider.",
    icon: Cloud,
  },
  security: {
    label: "Security",
    title: "Security",
    description: "Control how and when your vault locks itself.",
    icon: Shield,
  },
};
type SectionId = keyof typeof SECTIONS;

export default function Settings() {
  const router = useRouter();
  const session = useAppStore((state) => state.session);
  const isLocked = useAppStore((state) => state.vault.status !== "unlocked");
  const [googleActionLoading, setGoogleActionLoading] = useState(false);
  const [googleError, setGoogleError] = useState<string | null>(null);
  const [mirrorFeedback, setMirrorFeedback] = useState<MirrorFeedback | null>(null);
  const [section, setSection] = useState<SectionId>("extension");
  const [requestedProvider, setRequestedProvider] = useState<string | null>(null);

  useAuthGuard(["unlocked"]);

  const googleStatusQuery = useCloudStatus(session?.vaultId ?? "anonymous", !!session?.vaultId && !isLocked);
  const providersQuery = useCloudProviders();
  const credentialsQuery = useCloudCredentials(!!session?.vaultId && !isLocked);
  const googleBindingQuery = useCloudBinding(session?.vaultId, !!session?.vaultId && !isLocked);
  const googleStatus = googleStatusQuery.data ?? null;
  const googleBinding = googleBindingQuery.data ?? null;
  const activeProviderKind = googleBinding?.provider_kind ?? providersQuery.data?.[0]?.kind;
  const selectedProviderKind = requestedProvider ?? activeProviderKind;
  const activeProviderLabel = activeProviderKind ? providerLabelForKind(activeProviderKind) : "cloud provider";
  const selectedProviderLabel = selectedProviderKind ? providerLabelForKind(selectedProviderKind) : "cloud provider";
  const googleConfigured = providersQuery.isSuccess ? providersQuery.data.length > 0 : null;
  const disconnectCloudMutation = useDisconnectCloud();
  const mirrorMutation = useMirrorCloudVault(session?.vaultId);

  const { icon: SectionIcon, ...sectionMeta } = SECTIONS[section];

  // Derived once so the status line, the detail line, and the "Back up now"
  // affordance all agree. Falls back to a pending view if the binding has not
  // loaded yet (e.g. right after connecting), rather than claiming "up to date".
  const backupView: BackupView = googleBinding?.remote_file_id
    ? describeBackup(googleBinding)
    : describeBackupLoading();

  const refreshGoogle = async () => {
    await Promise.all([googleStatusQuery.refetch(), googleBindingQuery.refetch()]);
  };

  const handleEnableGoogleDrive = async () => {
    if (!session?.vaultId) return;
    setGoogleActionLoading(true);
    setGoogleError(null);
    try {
      if (!selectedProviderKind) throw new Error("Cloud backup is not configured on this server.");
      await enableCloudForVault(session.vaultId, selectedProviderKind);
      setRequestedProvider(null);
      await refreshGoogle();
    } catch (e: any) {
      const message = e?.response?.data?.error_msg || e?.message || "Failed to enable cloud backup";
      // The OAuth helper starts a browser redirect as part of this flow.
      if (!message.includes("Redirecting")) setGoogleError(message);
    } finally {
      setGoogleActionLoading(false);
    }
  };

  const handleDisconnectGoogle = async () => {
    setGoogleActionLoading(true);
    setGoogleError(null);
    try {
      await disconnectCloudMutation.mutateAsync();
      await refreshGoogle();
    } catch (e: any) {
      setGoogleError(e?.response?.data?.error_msg || e?.message || "Failed to disconnect");
    } finally {
      setGoogleActionLoading(false);
    }
  };

  const handleBackupNow = async () => {
    setGoogleError(null);
    try {
      const { mirror } = await mirrorMutation.mutateAsync();
      setMirrorFeedback(describeMirrorResult(mirror));
    } catch (e: any) {
      // Surface the code rather than the raw axios error: it may carry request
      // configuration, and the code is the part a user can act on.
      setMirrorFeedback(describeMirrorNetworkFailure(e?.response?.data?.code));
    }
  };

  return (
    <View className="flex-1 flex-row bg-panel">
      <View className="w-56 border-r border-border bg-panel px-3 py-5">
        <View className="mb-7 flex-row items-center px-3 py-2">
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Back to vault"
            className="rounded-lg p-1 hover:bg-card"
            onPress={() => router.replace("/home" as any)}
          >
            <ArrowLeft size={16} color="#a1a1aa" />
          </Pressable>
          <Text className="ml-2 text-base font-semibold text-primary-text">Settings</Text>
        </View>
        <View className="gap-1">
          {(Object.keys(SECTIONS) as SectionId[]).map((id) => {
            const { label, icon: Icon } = SECTIONS[id];
            const active = section === id;
            return (
              <Pressable
                key={id}
                accessibilityRole="button"
                accessibilityState={{ selected: active }}
                className={`flex-row items-center rounded-lg px-3 py-2.5 hover:bg-card ${
                  active ? "bg-card" : ""
                }`}
                onPress={() => setSection(id)}
              >
                <Icon size={16} color={active ? "#e4e4e7" : "#a1a1aa"} />
                <Text className={`ml-3 text-sm font-medium ${active ? "text-primary-text" : "text-muted-text"}`}>
                  {label}
                </Text>
              </Pressable>
            );
          })}
        </View>
      </View>

      <ScrollView className="flex-1" contentContainerClassName="mx-auto w-full max-w-4xl px-8 py-10">
        <View className="mb-8">
          <View className="mb-2 flex-row items-center">
            <SectionIcon size={20} color="#a1a1aa" />
            <Text className="ml-3 text-2xl font-semibold text-primary-text">{sectionMeta.title}</Text>
          </View>
          <Text className="text-sm text-muted-text">{sectionMeta.description}</Text>
        </View>

        {section === "extension" ? (
          <ExtensionPairing />
        ) : section === "security" ? (
          <>
            <AutolockSection />
            <DeviceUnlockSection />
          </>
        ) : (
          <>
          <View className="mb-4 rounded-2xl border border-border bg-card p-5">
            <Text className="mb-3 text-sm font-semibold text-primary-text">Cloud provider</Text>
            {providersQuery.isPending ? <Text className="text-sm text-muted-text">Loading providers…</Text> :
              (providersQuery.data ?? []).length === 0 ? <Text className="text-sm text-muted-text">Cloud backup is not configured on this server.</Text> :
              providersQuery.data?.map((provider) => {
                const credential = credentialsQuery.data?.find((item) => item.kind === provider.kind);
                const active = googleBinding?.provider_kind === provider.kind;
                const selected = selectedProviderKind === provider.kind;
                return <Pressable key={provider.kind} accessibilityRole="button" accessibilityState={{ selected }}
                  className={`mb-2 flex-row items-center justify-between rounded-lg border px-4 py-3 ${selected ? "border-accent-line bg-surface" : "border-border"}`}
                  onPress={() => setRequestedProvider(provider.kind)}>
                  <View>
                    <Text className="text-sm font-semibold text-primary-text">{providerLabelForKind(provider.kind)}</Text>
                    <Text className="mt-1 text-xs text-muted-text">{active ? "Active backup" : credential ? `Connected${credential.email ? ` · ${credential.email}` : ""} · retained for switching` : "Not connected"}</Text>
                  </View>
                  <Text className="text-xs text-muted-text">{selected ? "Selected" : "Choose"}</Text>
                </Pressable>;
              })}
            {selectedProviderKind && selectedProviderKind !== activeProviderKind && (
              <Pressable className="mt-2 self-start rounded-lg bg-surface border border-border-strong px-4 py-2.5"
                onPress={handleEnableGoogleDrive} disabled={googleActionLoading}>
                <Text className="text-sm font-medium text-primary-text">{googleActionLoading ? "Switching…" : `Switch to ${selectedProviderLabel}`}</Text>
              </Pressable>
            )}
          </View>
          <View className="rounded-2xl border border-border bg-card p-5">
            <View className="mb-1 flex-row items-center">
              <Cloud size={18} color="#c4b5fd" />
              <Text className="ml-2 text-base font-semibold text-primary-text">{activeProviderLabel}</Text>
            </View>
            <Text className="mb-4 text-sm text-muted-text">
              Store an encrypted copy of this vault with {activeProviderLabel}.
            </Text>

            {googleConfigured === false ? (
              <Text className="text-sm text-muted-text">Cloud backup is not configured on this server.</Text>
            ) : googleStatus?.connected && googleBinding?.remote_file_id ? (
              <View>
                {/* Real backup state, derived from cloud_binding — the server
                    mirrors each committed vault write to the active provider after the CAS,
                    so this reflects whether that mirror actually kept up. */}
                <View className="mb-2 flex-row items-center">
                  <View className={`mr-2 h-2 w-2 rounded-full ${backupView.dot}`} />
                  <Text className="text-sm font-medium" style={{ color: BACKUP_TITLE_COLOR[backupView.tone] }}>
                    {backupView.title}
                  </Text>
                </View>
                <Text className="text-sm text-muted-text">{googleStatus.email || `${activeProviderLabel} account connected`}</Text>
                <Text className="mt-1 text-sm text-muted-text">{backupView.detail}</Text>
                <Text className="mt-1 text-xs text-muted-text" numberOfLines={1}>
                  Remote file: {googleBinding.remote_file_id}
                </Text>
                {googleBinding.remote_revision && (
                  <Text className="mt-1 text-xs text-muted-text">Provider revision: {googleBinding.remote_revision.slice(0, 8)}</Text>
                )}

                {mirrorFeedback && (
                  <Text
                    className="mt-3 text-sm"
                    style={{ color: BACKUP_TITLE_COLOR[mirrorFeedback.tone] }}
                  >
                    {mirrorFeedback.text}
                  </Text>
                )}

                <View className="mt-4 flex-row gap-2">
                  <Pressable
                    className="rounded-lg bg-surface border border-border-strong px-4 py-2"
                    onPress={handleBackupNow}
                    disabled={mirrorMutation.isPending || backupView.tone === "ok"}
                    accessibilityLabel={`Back up this vault to ${activeProviderLabel} now`}
                  >
                    <Text className="text-sm text-primary-text">
                      {mirrorMutation.isPending ? "Backing up…" : "Back up now"}
                    </Text>
                  </Pressable>
                  <Pressable
                    className="rounded-lg border border-border-strong px-4 py-2"
                    onPress={handleDisconnectGoogle}
                    disabled={googleActionLoading || disconnectCloudMutation.isPending}
                  >
                    <Text className="text-sm text-primary-text">
                      {googleActionLoading || disconnectCloudMutation.isPending ? "Disconnecting…" : `Disconnect ${activeProviderLabel}`}
                    </Text>
                  </Pressable>
                </View>
              </View>
            ) : googleStatus?.connected ? (
              <View>
                <Text className="mb-1 text-sm font-medium text-yellow-400">{activeProviderLabel} account connected</Text>
                <Text className="mb-3 text-sm text-muted-text">{googleStatus.email} — backup is not enabled yet.</Text>
                <Pressable
                  className="self-start rounded-lg bg-surface border border-border-strong px-4 py-2.5"
                  onPress={handleEnableGoogleDrive}
                  disabled={googleActionLoading}
                >
                  <Text className="text-sm font-medium text-primary-text">{googleActionLoading ? "Enabling…" : "Enable encrypted sync"}</Text>
                </Pressable>
              </View>
            ) : (
              <View>
                <Text className="mb-3 text-sm text-muted-text">
                  {googleStatusQuery.isPending ? "Checking connection…" : "Not connected"}
                </Text>
                <Pressable
                  className="self-start rounded-lg bg-surface border border-border-strong px-4 py-2.5"
                  onPress={handleEnableGoogleDrive}
                  disabled={googleActionLoading || googleStatusQuery.isPending}
                >
                  <Text className="text-sm font-medium text-primary-text">
                    {googleActionLoading ? "Connecting…" : `Connect ${selectedProviderLabel}`}
                  </Text>
                </Pressable>
              </View>
            )}
            {googleError && <Text className="mt-3 text-sm text-red-400">{googleError}</Text>}
          </View>
          </>
        )}
      </ScrollView>
    </View>
  );
}
