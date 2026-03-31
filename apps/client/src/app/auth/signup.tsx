import { Link } from "expo-router";
import { useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";
import { createSingupPayload } from "../../lib/crypto/index.web";
import { useSignUp } from "../../lib/queries/SignUp/query";

const TEST_VAULT = {
  items: [
    {
      site: "Google",
      username: "test@example.com",
      password: "password",
    },
    {
      site: "Facebook",
      username: "test@example.com",
      password: "password",
    },
    {
      site: "Twitter",
      username: "test@example.com",
      password: "password",
    },
  ],
};
const TEST_VAULT_JSON = JSON.stringify(TEST_VAULT);

export default function SignUp() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const signUp = useSignUp();

  const onSubmit = async () => {
    setError(null);
    try {
      console.log("SignUp submit", { email });
      const payload = await createSingupPayload(password, email, TEST_VAULT_JSON);
      console.log("SignUp payload ready", payload);
      await signUp.mutateAsync(payload);
    } catch (err) {
      console.error("SignUp submit failed", err);
      setError(err instanceof Error ? err.message : "Sign up failed.");
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
        disabled={signUp.isPending}
      >
        <Text className="text-white">
          {signUp.isPending ? "Creating..." : "Create account"}
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
