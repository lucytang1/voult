import { useState } from "react";
import { Pressable, Text, View, ActivityIndicator } from "react-native";
import { useRouter } from "expo-router";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { startGoogleAuth, redirectToGoogleAuth } from "@/src/lib/google/api";

/**
 * Landing / first-run entry (Flow C).
 *
 * No email is ever collected. A brand-new user (no session, no locally-known
 * vault) chooses between:
 *   - Create a new vault locally (generates a vault id on-device), or
 *   - Import an existing vault from Google Drive (starts the OAuth pending
 *     flow; the vault is later unlocked by vault id + master password — no
 *     email field is shown).
 * A secondary "Restore existing vault" link covers the paste-a-vault-id case.
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
    <View className="flex-1 items-center justify-center bg-black px-6">
      <Text className="text-white text-3xl font-bold mb-2">Voult</Text>
      <Text className="text-gray-400 text-sm mb-10 text-center">
        Your password vault. No account email required.
      </Text>

      <Pressable
        className="w-full rounded-xl bg-purple-600 py-4 items-center mb-4"
        onPress={() => router.push("/vault/create" as any)}
      >
        <Text className="text-white font-medium text-lg">Create new vault</Text>
        <Text className="text-purple-200 text-xs mt-1">Stays on this device until you enable sync</Text>
      </Pressable>

      <Pressable
        className={`w-full rounded-xl py-4 items-center mb-6 border ${
          googleAvailable === false
            ? "bg-[#1e1e36] border-[#2a2a4a] opacity-60"
            : "bg-[#2a2a4a] border-[#3a3a5a]"
        }`}
        onPress={onGoogleDrive}
        disabled={googleLoading || googleAvailable === false}
      >
        {googleLoading ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <>
            <Text className="text-white font-medium text-lg">Continue with Google Drive</Text>
            <Text className="text-gray-400 text-xs mt-1">
              Import an existing vault from your Drive
            </Text>
          </>
        )}
      </Pressable>

      {googleError && <Text className="text-red-400 text-sm mb-4">{googleError}</Text>}

      <Pressable className="mt-2" onPress={() => router.push("/auth/login" as any)}>
        <Text className="text-blue-400 text-sm">Restore an existing vault by vault id</Text>
      </Pressable>
    </View>
  );
}
