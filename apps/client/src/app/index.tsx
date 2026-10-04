import { useState } from "react";
import { Pressable, Text, View, ActivityIndicator } from "react-native";
import { useRouter } from "expo-router";
import { GoogleDriveIcon } from "../../assets/images/GoogleDriveIcon";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { startGoogleAuth, redirectToGoogleAuth } from "@/src/lib/google/api";

/**
 * Landing / first-run entry (Case 1: no session).
 *
 * Mirrors the Paper artboard "Landing - / - Desktop" (1440x900):
 * left black copy panel + right rail action panel with an auth card.
 * All visuals are NativeWind classes backed by the landing tokens in
 * global.css (@theme) — no inline styles. Panels stack on narrow screens.
 *
 * When no session is present the user chooses exactly two options:
 *   1) Create new vault locally -> enter master password -> vault created
 *      (can later enable cloud sync from Settings/Home).
 *   2) Use Cloud sync -> Google OAuth -> list Drive vaults -> select vault
 *      -> enter master password -> decrypt & download locally.
 * No vault-id input is ever shown.
 */
export default function Landing() {
  // Landing is only for signed-out users; locked users go to /lock,
  // unlocked users go straight to /home.
  useAuthGuard(["not_authenticated"]);
  const router = useRouter();
  const [googleLoading, setGoogleLoading] = useState(false);
  const [googleError, setGoogleError] = useState<string | null>(null);
  const [googleAvailable, setGoogleAvailable] = useState<boolean | null>(null);

  const onGoogleDrive = async () => {
    setGoogleError(null);
    setGoogleLoading(true);
    try {
      // Start the pre-session (pending) OAuth flow — no email is sent. The
      // vault is imported later by vault id + master password in the chooser.
      const { auth_url } = await startGoogleAuth();
      redirectToGoogleAuth(auth_url);
    } catch (e: any) {
      const code = e?.response?.data?.code as string | undefined;
      if (code === "GOOGLE_NOT_CONFIGURED") {
        setGoogleAvailable(false);
        setGoogleError("Google Drive is not configured on this server.");
      } else {
        setGoogleError(e?.response?.data?.error_msg || e?.message || "Failed to start Google Drive");
      }
      setGoogleLoading(false);
    }
  };

  return (
    <View className="flex-1 flex-col bg-ground font-app md:flex-row">
      {/* Left — copy panel */}
      <View className="flex-1 justify-center bg-ground px-6 py-12 md:px-[72px] md:py-[80px]">
        <View>
          <Text className="text-[80px] font-normal leading-[68px] tracking-[-0.02em] text-white">
            Voult
          </Text>
          <View className="pt-4">
            <Text className="text-[36px] font-normal leading-[44px] tracking-[-0.02em] text-white">
              {"Setup Voult to start\nsaving logins."}
            </Text>
          </View>
          <View className="max-w-120 pt-4">
            <Text className="text-[17px] font-normal leading-6.5 text-muted">
              Only you hold the key. No account, no plaintext ever leaves this device.
            </Text>
          </View>
        </View>
      </View>

      {/* Right — actions rail */}
      <View className="w-full items-center justify-center border-border border-t bg-rail p-6 md:w-150 md:border-l md:border-t-0 md:p-12">
        {/* Auth card */}
        <View className="w-full max-w-100 rounded-[20px] border border-border-strong bg-panel px-8 py-9">
          <Text className="text-center text-[26px] font-normal leading-[32px] tracking-[-0.01em] text-white">
            Let&apos;s get started!
          </Text>
          <View className="pt-2">
            <Text className="text-center text-[14px] font-normal leading-[20px] text-muted">
              Create a new vault or import from Drive to continue
            </Text>
          </View>

          {/* Create button */}
          <Pressable
            className="mt-7 w-full items-center rounded-[14px] bg-accent px-5 py-3 shadow-[0px_8px_32px_#7C3AED59]"
            onPress={() => router.push("/auth/signup" as any)}
          >
            <Text className="text-[17px] font-semibold leading-[24px] text-white">
              Create new vault
            </Text>
            <View className="pt-1">
              <Text className="text-[12px] font-normal leading-[16px] text-accent-soft">
                Stays on this device until you enable sync
              </Text>
            </View>
          </Pressable>

          {/* Divider */}
          <View className="w-full flex-row items-center gap-3 py-5">
            <View className="h-[1px] flex-1 bg-border" />
            <Text className="text-[13px] font-normal leading-[16px] text-faint">or</Text>
            <View className="h-[1px] flex-1 bg-border" />
          </View>

          {/* Google button */}
          <Pressable
            className={`w-full flex-row items-center justify-center gap-[14px] rounded-[14px] border border-border-strong bg-card px-5 py-3 ${
              googleAvailable === false ? "opacity-60" : ""
            }`}
            onPress={onGoogleDrive}
            disabled={googleLoading || googleAvailable === false}
          >
            {googleLoading ? (
              <ActivityIndicator color="#fff" />
            ) : (
              <>
                {/* Drive badge */}
                <View className="h-7 w-7 shrink-0 items-center justify-center rounded-lg">
                  <GoogleDriveIcon width={28} height={26} />
                </View>
                {/* Labels */}
                <View className="items-start">
                  <Text className="text-[16px] font-semibold leading-[22px] text-white">
                    Continue with Google Drive
                  </Text>
                  <View className="pt-[2px]">
                    <Text className="text-[12px] font-normal leading-[16px] text-muted">
                      Import an existing vault from your Drive
                    </Text>
                  </View>
                </View>
              </>
            )}
          </Pressable>

          {googleError && (
            <Text className="mt-4 text-center text-sm text-red-400">{googleError}</Text>
          )}
        </View>
      </View>
    </View>
  );
}
