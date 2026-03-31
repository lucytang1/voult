import { Link, useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";
import { createEncryptionKey, createLoginPayload, createAuthKey } from "../../lib/crypto/index.web";
import { useLogIn } from "../../lib/queries/logIn/query";
import { useGetCryptoParams } from "../../lib/queries/cryptoParams/query";
import { updateEncryptionKey, updateAuthKey } from "../../lib/state";

export default function LogIn() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const getCryptoParams = useGetCryptoParams(email, false);
  const logIn = useLogIn();
  const router = useRouter();

  const onContinue = async () => {
    setError(null);
    try {
      if (!getCryptoParams.data?.salt) {
        const result = await getCryptoParams.refetch();
        if (!result.data?.salt) {
          setError("Failed to get salt.");
        }
        return;
      }
      const payload = await createLoginPayload(
        email,
        password,
        getCryptoParams.data.salt,
        getCryptoParams.data.iterations
      );

      await logIn.mutateAsync(payload, {
        onSuccess: async () => {
          updateEncryptionKey(
            await createEncryptionKey(
              email,
              password,
              getCryptoParams.data.salt,
              getCryptoParams.data.iterations
            )
          );
          updateAuthKey(
            await createAuthKey(
              email,
              password,
              getCryptoParams.data.salt,
              getCryptoParams.data.iterations
            )
          );
          router.navigate("/home" as any);
        },
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to log in.");
    }
  };

  return (
    <View className="flex-1 items-center justify-center bg-black px-6">
      <Text className="text-white text-xl mb-4">Log in</Text>
      <TextInput
        className="w-full rounded-md bg-white px-3 py-2 mb-3"
        placeholder="Email"
        placeholderTextColor="#666"
        autoCapitalize="none"
        keyboardType="email-address"
        value={email}
        onChangeText={setEmail}
        editable={!getCryptoParams.isFetching && !getCryptoParams.data?.salt}
      />

      {getCryptoParams.data?.salt ? (
        <TextInput
          className="w-full rounded-md bg-white px-3 py-2 mb-4"
          placeholder="Password"
          placeholderTextColor="#666"
          secureTextEntry
          value={password}
          onChangeText={setPassword}
        />
      ) : null}

      <Pressable
        className="w-full rounded-md bg-blue-600 py-2 items-center"
        onPress={onContinue}
        disabled={
          getCryptoParams.isFetching ||
          logIn.isPending ||
          !email ||
          (getCryptoParams.data?.salt ? !password : false)
        }
      >
        <Text className="text-white">
          {getCryptoParams.isFetching || logIn.isPending
            ? "Loading..."
            : getCryptoParams.data?.salt
            ? "Log in"
            : "Continue"}
        </Text>
      </Pressable>

      {error ? <Text className="text-red-400 mt-3">{error}</Text> : null}

      <Link href="/" asChild>
        <Pressable className="mt-4">
          <Text className="text-blue-400">Back to home</Text>
        </Pressable>
      </Link>
      <Link href={"/auth/signup" as any} asChild>
        <Pressable className="mt-2">
          <Text className="text-blue-400">Create an account</Text>
        </Pressable>
      </Link>
    </View>
  );
}
