import { useEffect, useState } from "react";
import { Pressable, Text, View, ActivityIndicator } from "react-native";
import { useRouter } from "expo-router";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { listCloudProviders, redirectToCloudAuth, startCloudAuth, type CloudProviderInfo } from "@/src/lib/cloud/api";
import { providerLabel, cloudProviderRegistry, CloudProviderFallbackIcon } from "@/src/lib/cloud/providers";

/**
 * Landing / first-run entry (Case 1: no session).
 *
 * Mirrors the Paper artboard "Landing - / - Desktop" (1440x900):
 * a full-height copy panel on the near-black ground, and a 600px action
 * rail in --color-panel holding a centred auth card. All visuals are
 * NativeWind classes backed by the palette in global.css (@theme) — no
 * inline styles. The two panels stack on narrow screens.
 *
 * Note the deliberate asymmetry in the card's two calls to action: the
 * primary path (create a vault locally) is an outline, and the accent
 * fill is spent on the cloud backup import. "Local first" is the product,
 * so it should not wear the loudest colour.
 *
 * When no session is present the user chooses exactly two options:
 *   1) Create a new vault locally -> enter master password -> vault created
 *      (can later enable cloud sync from Settings/Home).
 *   2) Use Cloud sync -> cloud provider OAuth -> list provider vaults -> select vault
 *      -> enter master password -> decrypt & download locally.
 * No vault-id input is ever shown.
 */
export default function Landing() {
  // Landing is only for signed-out users; locked users go to /lock,
  // unlocked users go straight to /home.
  useAuthGuard(["no_vault"]);
  const router = useRouter();
  const [cloudLoading, setCloudLoading] = useState(false);
  const [cloudError, setCloudError] = useState<string | null>(null);
  const [showProviderPicker, setShowProviderPicker] = useState(false);
  const [providers, setProviders] = useState<CloudProviderInfo[] | null>(null);

  useEffect(() => {
    let active = true;
    listCloudProviders().then((items) => { if (active) setProviders(items); })
      .catch(() => { if (active) setProviders([]); });
    return () => { active = false; };
  }, []);

  const onCloudProvider = async (provider: CloudProviderInfo) => {
    setCloudError(null);
    setCloudLoading(true);
    try {
      // Start the pre-session (pending) OAuth flow — no email is sent. The
      // vault is imported later by vault id + master password in the chooser.
      const { auth_url } = await startCloudAuth(provider.kind);
      redirectToCloudAuth(auth_url);
    } catch (e: any) {
      setCloudError(e?.response?.data?.error_msg || e?.message || `Failed to start ${providerLabel(provider)}`);
      setCloudLoading(false);
    }
  };

  return (
    <View className="flex-1 flex-col bg-ground font-app md:flex-row">
      {/* Left — copy panel */}
      <View className="flex-1 justify-center bg-ground px-6 py-12 md:px-18 md:py-20">
        <View>
          <Text className="text-[80px] font-normal leading-[68px] tracking-[-0.02em] text-primary-text">
            Voult
          </Text>
          <View className="pt-4">
            <Text className="text-[34px] font-normal leading-[40px] tracking-[-0.02em] text-primary-text">
              {"Setup Voult to start\nsaving logins."}
            </Text>
          </View>
          <View className="max-w-120 pt-4">
            <Text className="text-[17px] font-normal leading-6.5 text-muted-text">
              Only you hold the key. No account, no plaintext ever leaves this device.
            </Text>
          </View>
        </View>
      </View>

      {/* Right — actions rail. No left border on desktop: the ground/panel
          step already separates the panels, and the artboard shows a clean
          seam. The hairline only matters when the panels stack. */}
      <View className="w-full items-center justify-center border-border border-t bg-panel p-6 md:w-150 md:border-t-0 md:p-12">
        {/* Auth card */}
        <View className="w-full max-w-100 rounded-[20px] border border-border bg-card px-8 py-9">
          <Text className="text-center text-[26px] font-normal leading-[32px] tracking-[-0.01em] text-primary-text">
            Let&apos;s get started!
          </Text>
          <View className="pt-2">
            {/* Capped width so the sentence breaks onto two lines as in the
                artboard instead of filling the card's full measure. */}
            <Text className="mx-auto max-w-[270px] text-center text-[14px] font-normal leading-[20px] text-muted-text">
              Create a new vault or import an encrypted cloud backup to continue
            </Text>
          </View>

          {/* Create button — outline, the quieter of the two actions.
              The edge is what makes it read as a control: fill contrast on
              this palette is ~1:1 by design, so it takes the emphatic border. */}
          <Pressable
            className="mt-7 w-full items-center justify-center rounded-[10px] border border-border-strong bg-surface px-5 py-2.5"
            onPress={() => router.push("/auth/signup" as any)}
          >
            <Text className="text-[16px] font-semibold leading-5 text-primary-text">
              Create local vault
            </Text>
          </Pressable>

          {/* Divider */}
          <View className="w-full flex-row items-center gap-3 py-4">
            <View className="h-[1px] flex-1 bg-border" />
            <Text className="text-[13px] font-normal leading-[16px] text-muted-text">or</Text>
            <View className="h-[1px] flex-1 bg-border" />
          </View>

          {/* Cloud backup button opens the configured provider picker. */}
          <Pressable
            className="w-full flex-row items-center justify-center gap-[10px] rounded-[10px] bg-accent px-5 py-3"
            onPress={() => { setCloudError(null); setShowProviderPicker(true); }}
            disabled={cloudLoading}
          >
            {cloudLoading ? (
              <ActivityIndicator color="#F2F4F7" />
            ) : (
              <Text className="text-[16px] font-semibold leading-6 text-primary-text">Continue with cloud backup</Text>
            )}
          </Pressable>

          {showProviderPicker && (
            <View className="mt-4 rounded-xl border border-border bg-surface p-4">
              <Text className="mb-3 text-sm font-semibold text-primary-text">Choose a cloud provider</Text>
              {providers === null ? <ActivityIndicator /> : providers.length === 0 ? (
                <Text className="text-sm text-muted-text">Cloud backup is not configured on this server.</Text>
              ) : providers.map((provider) => {
                const Icon = cloudProviderRegistry[provider.kind]?.icon ?? CloudProviderFallbackIcon;
                return <Pressable key={provider.kind} className="mb-2 flex-row items-center gap-3 rounded-lg border border-border px-4 py-3" onPress={() => onCloudProvider(provider)}>
                  {Icon ? <Icon width={22} height={22} /> : null}
                  <Text className="text-sm font-semibold text-primary-text">{providerLabel(provider)}</Text>
                </Pressable>;
              })}
              <Pressable onPress={() => setShowProviderPicker(false)} className="mt-1 self-center px-3 py-2"><Text className="text-xs text-muted-text">Cancel</Text></Pressable>
            </View>
          )}

          {cloudError && (
            <Text className="mt-4 text-center text-sm text-red-400">{cloudError}</Text>
          )}

        </View>
      </View>
    </View>
  );
}
