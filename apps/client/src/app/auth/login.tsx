import { Link, useRouter } from "expo-router";
import { Pressable, Text, View } from "react-native";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";

/**
 * Deprecated vault-id login.
 * The desired flow has no vault-id input: users with no selected vault go to "/"
 * and choose "Create new vault" or "Continue with Google Drive" (then master
 * password). This route now redirects to "/".
 */
export default function LogIn() {
  useAuthGuard(["no_vault"]);
  const router = useRouter();

  return (
    <View className="flex-1 items-center justify-center bg-ground px-6">
      <Text className="text-primary-text text-xl mb-2">Vault-id login is deprecated</Text>
      <Text className="text-muted-text text-sm mb-6 text-center">
        Use the landing page instead: create a new vault locally or restore from Google Drive — no vault id needed.
      </Text>
      <Pressable className="w-full rounded-md bg-surface border border-border-strong py-3 items-center" onPress={() => router.replace("/" as any)}>
        <Text className="text-primary-text font-medium">Go to landing</Text>
      </Pressable>
      <Link href={"/auth/signup" as any} asChild>
        <Pressable className="mt-4">
          <Text className="text-accent-text">Create a new vault</Text>
        </Pressable>
      </Link>
    </View>
  );
}
