import { useState } from "react";
import { Pressable, ScrollView, Text, View } from "react-native";
import { useRouter } from "expo-router";
import { ArrowLeft, Blocks, CloudBackup, FolderLock, Vault, type LucideIcon } from "lucide-react";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { ExtensionPairing } from "@/src/lib/extension-pair";
import { AutolockSection } from "@/src/lib/settings/autolock-section";
import { DeviceUnlockSection } from "@/src/lib/settings/device-unlock-section";
import { RecoveryKeySection } from "@/src/lib/settings/recovery-key-section";
import { BackupSection } from "@/src/lib/settings/backup-section";
import { VaultSection } from "@/src/lib/settings/vault-section";

// The left rail, the page header and the content pane all read from this one
// map, so adding a section is a single entry rather than three parallel edits.
const SECTIONS: Record<string, { label: string; title: string; description: string; icon: LucideIcon }> = {
  vault: {
    label: "Vault",
    title: "Vault",
    description: "Name this vault and find its permanent identifier.",
    icon: Vault,
  },
  extension: {
    label: "Extension",
    title: "Extension",
    description: "Connect Voult to your browser extension.",
    icon: Blocks,
  },
  provider: {
    label: "Backup",
    title: "Backup",
    description: "Keep an encrypted copy of this vault in your cloud provider.",
    icon: CloudBackup,
  },
  security: {
    label: "Security",
    title: "Security",
    description: "Control how and when your vault locks itself.",
    icon: FolderLock,
  },
};
type SectionId = keyof typeof SECTIONS;

export default function Settings() {
  const router = useRouter();
  const [section, setSection] = useState<SectionId>("vault");

  useAuthGuard(["unlocked"]);

  const sectionMeta = SECTIONS[section];

  return (
    <View className="flex-1 flex-row bg-ground">
      {/* The rail is orientation, not a stack of buttons. A single 32px row
          rhythm, one icon column, a quiet selection fill; the rail and the
          rows share the same inset so every glyph lands on one left edge. */}
      <View className="w-56 border-r-[0.5px] border-hairline-accent bg-ground px-3 pt-3 pb-4">
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Back to vault"
          className="group self-start flex-row items-center gap-2 rounded-md border border-transparent px-2 py-1.5 hover:bg-surface2/60 focus-visible:border-hairline focus-visible:bg-surface2/60 focus-visible:outline-none"
          onPress={() => router.replace("/home" as any)}
        >
          <ArrowLeft
            size={16}
            strokeWidth={1.75}
            className="text-muted-text group-hover:text-primary-text group-focus-visible:text-primary-text"
          />
          <Text className="text-xs font-medium text-muted-text group-hover:text-primary-text group-focus-visible:text-primary-text">
            Back
          </Text>
        </Pressable>
        {/* Back stays pinned to the top; the section list sits in the middle of
            the space it leaves, so the rail reads as a directory rather than a
            menu that ran out of items. */}
        <View className="flex-1 justify-center gap-0.5">
          {(Object.keys(SECTIONS) as SectionId[]).map((id) => {
            const { label, icon: Icon } = SECTIONS[id];
            const active = section === id;
            return (
              <Pressable
                key={id}
                accessibilityRole="button"
                accessibilityState={{ selected: active }}
                // A hovered row lifts just enough to answer the pointer; the
                // selected row keeps the stronger fill and the brighter label.
                className={`group flex-row items-center gap-2 rounded-md border px-2 h-8 focus-visible:border-hairline focus-visible:outline-none ${
                  active
                    ? "border-transparent bg-surface2"
                    : "border-transparent hover:bg-surface2/60 focus-visible:bg-surface2/60"
                }`}
                onPress={() => setSection(id)}
              >
                {active && (
                  // A small white tick on the trailing edge: the fill alone is
                  // quiet, this is the part that says "you are here".
                  <View className="absolute right-1 top-1.5 bottom-1.5 w-0.5 rounded-full bg-primary-text" />
                )}
                <Icon
                  size={16}
                  strokeWidth={1.75}
                  className={`${
                    active ? "text-primary-text" : "text-muted-text group-hover:text-primary-text"
                  } group-focus-visible:text-primary-text`}
                />
                <Text
                  className={`text-sm font-medium ${
                    active ? "text-primary-text" : "text-muted-text group-hover:text-primary-text"
                  } group-focus-visible:text-primary-text`}
                >
                  {label}
                </Text>
              </Pressable>
            );
          })}
        </View>
      </View>

      <ScrollView className="flex-1" contentContainerClassName="mx-auto w-full max-w-4xl px-8 py-10">
        <View className="mb-8">
          <Text className="mb-2 text-2xl font-semibold text-primary-text">{sectionMeta.title}</Text>
          <Text className="text-sm text-muted-text">{sectionMeta.description}</Text>
        </View>

        {section === "vault" ? (
          <VaultSection />
        ) : section === "extension" ? (
          <ExtensionPairing />
        ) : section === "security" ? (
          <>
            <AutolockSection />
            <RecoveryKeySection />
            <DeviceUnlockSection />
          </>
        ) : (
          <BackupSection />
        )}
      </ScrollView>
    </View>
  );
}
