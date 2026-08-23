import { Link, useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";
import { signupFlow } from "@/src/lib/auth/flows/signup";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { v4 as uuidv4 } from "uuid";
import {
  setSession,
  setVaultKey,
  updateDecryptedVault,
  updateVaultVersion,
} from "../../lib/state";

const TEST_VAULT = {
  items: [
    {
      id: uuidv4(),
      site: "Google",
      username: "test@example.com",
      password: "password",
    },
    {
      id: uuidv4(),
      site: "Facebook",
      username: "test@example.com",
      password: "password",
    },
    {
      id: uuidv4(),
      site: "Twitter",
      username: "test@example.com",
      password: "password",
    },
  ],
};
const TEST_VAULT_JSON = JSON.stringify(TEST_VAULT);

export default function SignUp() {
  // Signup is only for signed-out users; authenticated users are bounced
  // to /lock (locked) or /home (unlocked).
  useAuthGuard(["not_authenticated"]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const router = useRouter();

  const onSubmit = async () => {
    setError(null);
    setSubmitting(true);
    try {
      console.log("SignUp submit", { email });
      const result = await signupFlow(email, password, TEST_VAULT_JSON);
      setVaultKey(result.vaultKey);
      setSession(result.session);
      updateDecryptedVault(result.decryptedVault);
      updateVaultVersion(result.version);
      router.navigate("/home" as any);
    } catch (err) {
      console.error("SignUp submit failed", err);
      setError(err instanceof Error ? err.message : "Sign up failed.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <View className="flex-1 items-center justify-center bg-black px-6">
      <Text className="text-white text-xl mb-4">Sign up</Text>
      <TextInput
        className="w-full rounded-md bg-white px-3 py-2 mb-3"
        placeholder="Email"
        placeholderTextColor="#666"
        autoCapitalize="none"
        keyboardType="email-address"
        value={email}
        onChangeText={setEmail}
      />
      <TextInput
        className="w-full rounded-md bg-white px-3 py-2 mb-4"
        placeholder="Password"
        placeholderTextColor="#666"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
      />
      <Pressable
        className="w-full rounded-md bg-blue-600 py-2 items-center"
        onPress={onSubmit}
        disabled={submitting || !email || !password}
      >
        <Text className="text-white">
          {submitting ? "Creating..." : "Create account"}
        </Text>
      </Pressable>
      {error ? <Text className="text-red-400 mt-3">{error}</Text> : null}

      <Link href="/" asChild>
        <Pressable className="mt-4">
          <Text className="text-blue-400">Back to home</Text>
        </Pressable>
      </Link>
      <Link href={"/auth/login" as any} asChild>
        <Pressable className="mt-2">
          <Text className="text-blue-400">Already have an account?</Text>
        </Pressable>
      </Link>
    </View>
  );
}
