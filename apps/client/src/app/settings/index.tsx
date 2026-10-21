import { useState } from "react";
import { Pressable, ScrollView, Text, View } from "react-native";
import { useRouter } from "expo-router";
import { ArrowLeft, Cloud, Puzzle, Shield, Vault, type LucideIcon } from "lucide-react";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { ExtensionPairing } from "@/src/lib/extension-pair";
import { AutolockSection } from "@/src/lib/settings/autolock-section";
import { DeviceUnlockSection } from "@/src/lib/settings/device-unlock-section";
import { RecoveryKeySection } from "@/src/lib/settings/recovery-key-section";
import { ProviderSection } from "@/src/lib/settings/provider-section";
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
  const [section, setSection] = useState<SectionId>("vault");

  useAuthGuard(["unlocked"]);

  const sectionMeta = SECTIONS[section];

  return (
    <View className="flex-1 flex-row bg-ground">
      <View className="w-56 border-r-[0.5px] border-hairline-accent bg-ground px-3 py-5">
        <View className="mb-7">
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Back to vault"
            className="group inline-flex flex-row items-center rounded-lg px-3 py-2.5 hover:bg-surface1"
            onPress={() => router.replace("/home" as any)}
          >
            <ArrowLeft
              size={16}
              className="text-muted-text group-hover:text-primary-text"
            />
            <Text className="ml-3 text-sm font-medium text-muted-text group-hover:text-primary-text">
              Back
            </Text>
          </Pressable>
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
                className={`group flex-row items-center rounded-lg px-3 py-2.5 hover:bg-surface2 ${
                  active ? "bg-surface2" : ""
                }`}
                onPress={() => setSection(id)}
              >
                <Icon
                  size={16}
                  className={active ? "text-primary-text" : "text-muted-text group-hover:text-primary-text"}
                />
                <Text
                  className={`ml-3 text-sm font-medium ${
                    active ? "text-primary-text" : "text-muted-text group-hover:text-primary-text"
                  }`}
                >
                  {label}
                </Text>
              </Pressable>
            );
          })}
        </View>
      </View>

      <ScrollView className="flex-1" contentContainerClassName="mx-auto w-full max-w-4xl px-8 py-10">
        {section !== "provider" && (
          <View className="mb-8">
            <Text className="mb-2 text-2xl font-semibold text-primary-text">{sectionMeta.title}</Text>
            <Text className="text-sm text-muted-text">{sectionMeta.description}</Text>
          </View>
        )}

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
          <ProviderSection />
        )}
      </ScrollView>
    </View>
  );
}
