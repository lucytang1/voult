import { Link, useRouter } from "expo-router";
import { useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";
import { signupFlow } from "@/src/lib/auth/flows/signup";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { v4 as uuidv4 } from "uuid";
import { useSignUp } from "@/src/lib/queries/SignUp/query";
import {
  selectVaultSession,
  commitVaultUnlock,
  updateDecryptedVault,
  updateLockEpoch,
  updateVaultVersion,
} from "../../lib/state";

const TEST_VAULT = {
  items: [
    { id: uuidv4(), site: "Google", username: "test@example.com", password: "password" },
    { id: uuidv4(), site: "Facebook", username: "test@example.com", password: "password" },
    { id: uuidv4(), site: "Twitter", username: "test@example.com", password: "password" },
  ],
};
const TEST_VAULT_JSON = JSON.stringify(TEST_VAULT);

export default function SignUp() {
  // Signup is only for signed-out users; authenticated users are bounced
  // to /lock (locked) or /home (unlocked).
  useAuthGuard(["no_vault"]);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const router = useRouter();
  const signupMutation = useSignUp();

  const onSubmit = async () => {
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Master password must be at least 8 characters.");
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      // The vault id is generated client-side inside signupFlow — no email is
      // ever collected or sent to the server.
      const result = await signupFlow(password, TEST_VAULT_JSON, signupMutation.mutateAsync);
      // Select before installing the key: a newly created vault has no
      // prior selection, and commitVaultUnlock needs one to install against.
      selectVaultSession(result.session);
      commitVaultUnlock(result.vaultKey);
      updateLockEpoch(result.lockEpoch);
      updateDecryptedVault(result.decryptedVault);
      updateVaultVersion(result.version);
      router.navigate("/home" as any);
    } catch (err) {
      console.error("SignUp submit failed", err);
      setError(err instanceof Error ? err.message : "Sign up failed.");
    } finally {
      signupMutation.reset();
      setSubmitting(false);
    }
  };

  return (
    <View className="flex-1 items-center justify-center bg-ground px-6">
      <Text className="text-primary-text text-xl mb-4">Create new vault</Text>
      <Text className="text-muted-text text-xs mb-6">
        Your vault id is generated on this device. No email is required.
      </Text>
      <TextInput
        className="w-full rounded-md border border-border bg-surface px-3 py-2 mb-3 text-primary-text"
        placeholder="Master password (≥8 chars)"
        placeholderTextColor="#7E8590"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
      />
      <TextInput
        className="w-full rounded-md border border-border bg-surface px-3 py-2 mb-4 text-primary-text"
        placeholder="Confirm password"
        placeholderTextColor="#7E8590"
        secureTextEntry
        value={confirm}
        onChangeText={setConfirm}
      />
      <Pressable
        className="w-full rounded-md bg-surface border border-border-strong py-2 items-center"
        onPress={onSubmit}
        disabled={submitting || !password || !confirm}
      >
        <Text className="text-primary-text">
          {submitting ? "Creating..." : "Create vault"}
        </Text>
      </Pressable>
      {error ? <Text className="text-red-400 mt-3">{error}</Text> : null}

      <Link href="/" asChild>
        <Pressable className="mt-4">
          <Text className="text-accent-text">Back</Text>
        </Pressable>
      </Link>
      <Text className="text-muted-text text-xs mt-4 text-center">
        Already have a Drive backup? Go back and use "Continue with Google Drive" to restore it — no vault id needed.
      </Text>
    </View>
  );
}
