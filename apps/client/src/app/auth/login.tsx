import { Link, useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";
import { passwordLoginFlow } from "../../lib/auth/flows/login";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { useGetCryptoParams } from "../../lib/queries/cryptoParams/query";
import {
  setSession,
  setVaultKey,
  updateDecryptedVault,
  updateVaultVersion,
} from "../../lib/state";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default function LogIn() {
  // Login is only for signed-out users; authenticated users are bounced
  // to /lock (locked) or /home (unlocked).
  useAuthGuard(["not_authenticated"]);
  const [vaultId, setVaultId] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const getCryptoParams = useGetCryptoParams(vaultId, false);
  const router = useRouter();

  const onContinue = async () => {
    setError(null);
    if (!UUID_PATTERN.test(vaultId.trim())) {
      setError("Enter a valid vault id.");
      return;
    }
    try {
      if (!getCryptoParams.data?.salt) {
        const result = await getCryptoParams.refetch();
        if (!result.data?.salt) {
          setError("Failed to get crypto params for this vault.");
          return;
        }
      }
      setSubmitting(true);
      const result = await passwordLoginFlow(
        vaultId.trim(),
        password,
        getCryptoParams.data!.salt,
        getCryptoParams.data!.iterations
      );
      setVaultKey(result.vaultKey);
      setSession(result.session);
      updateDecryptedVault(result.decryptedVault);
      updateVaultVersion(result.version);
      router.navigate("/home" as any);
    } catch (err) {
      console.error("Login failed", err);
      setError(err instanceof Error ? err.message : "Failed to log in.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <View className="flex-1 items-center justify-center bg-black px-6">
      <Text className="text-white text-xl mb-4">Open existing vault</Text>
      <TextInput
        className="w-full rounded-md bg-white px-3 py-2 mb-3"
        placeholder="Vault id"
        placeholderTextColor="#666"
        autoCapitalize="none"
        value={vaultId}
        onChangeText={setVaultId}
        editable={!getCryptoParams.isFetching && !getCryptoParams.data?.salt}
      />

      {getCryptoParams.data?.salt ? (
        <TextInput
          className="w-full rounded-md bg-white px-3 py-2 mb-4"
          placeholder="Master password"
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
          submitting ||
          !vaultId ||
          (getCryptoParams.data?.salt ? !password : false)
        }
      >
        <Text className="text-white">
          {getCryptoParams.isFetching || submitting
            ? "Loading..."
            : getCryptoParams.data?.salt
            ? "Unlock"
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
          <Text className="text-blue-400">Create a new vault</Text>
        </Pressable>
      </Link>
    </View>
  );
}
