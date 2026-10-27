import { useState } from "react";
import { Pressable, Text, View } from "react-native";
import { useRouter } from "expo-router";
import { KeyRound } from "lucide-react";
import { useAppStore, captureSelectionEpoch } from "@/src/lib/state";
import { verifyRecoveryKey, describeRecoveryError } from "@/src/lib/auth/flows/recover";
import { readRecoveryFile } from "@/src/lib/auth/recovery-file";
import { RecoveryFilePicker } from "@/src/lib/components/recovery-file-picker";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";

/**
 * Recovery step 1 of 2 — open the recovery file.
 *
 * Reachable from three places: the landing page ("Recover a vault") on a fresh
 * machine, the lock screen ("Forgot your master password?"), and
 * `?recover=<vault_id>` in the URL, honoured by the bootstrap.
 *
 * The vault identity comes out of the FILE, not out of a text field. That is
 * what makes the file worth having: it carries the vault id alongside the key,
 * so a stranded user does not have to find and transcribe a 36-character UUID
 * before the app can do anything. The id in the recovery URL is still honoured
 * by the router, but the file is authoritative — a link that pointed at the
 * wrong vault must not be able to send the key somewhere else.
 *
 * Nothing is written and no session is established here. The user is only
 * asked for a new master password once this screen has confirmed the file's key
 * works — asking for it up front means a user with the wrong file invents a
 * password for nothing.
 */
export default function Recover() {
    // Valid from both "no vault selected" (fresh machine) and "locked" (cookie
    // expired). Pointless, and confusing, while unlocked.
    useAuthGuard(["no_vault", "locked"]);
    const router = useRouter();

    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [chosen, setChosen] = useState<string | null>(null);

    const onFile = async (file: File) => {
        setError(null);
        setBusy(true);
        try {
            const { vaultId, recoveryKey } = await readRecoveryFile(file);

            // A switch could land while the round-trips are in flight. Capture
            // the epoch before awaiting so a late result cannot be applied to
            // whatever vault is selected by the time it returns.
            const guard = captureSelectionEpoch();
            await verifyRecoveryKey({ vaultId, recoveryKey });

            if (!guard.stillCurrent()) {
                console.warn("Recovery verification discarded: selection changed");
                return;
            }

            setChosen(file.name);
            // Verified. The key is not carried through the URL — step 2 picks
            // up the vault key from the in-memory pending state.
            router.push("/recover-password" as any);
        } catch (e) {
            console.warn("Recovery file could not be used", e);
            setError(describeRecoveryError(e));
        } finally {
            setBusy(false);
        }
    };

    return (
        <View className="flex-1 items-center justify-center bg-ground px-6 py-10">
            <View className="w-12 h-12 rounded-full bg-card items-center justify-center mb-4 border border-border">
                <KeyRound size={22} color="#D89AC6" />
            </View>
            <Text className="text-primary-text text-xl font-bold mb-2">
                Recover a vault
            </Text>
            <Text className="text-muted-text text-sm mb-6 text-center max-w-md leading-5">
                Step 1 of 2 — open the recovery file you saved when this vault was
                created. It carries the key and the vault it belongs to. You will
                choose a new master password next.
            </Text>

            <RecoveryFilePicker onFile={onFile} busy={busy} />

            {chosen && !error ? (
                <Text className="text-muted-text text-xs mt-4 text-center max-w-md">
                    Using {chosen}
                </Text>
            ) : null}

            {error ? (
                <Text className="text-red-400 mt-4 text-center text-sm max-w-md leading-5">
                    {error}
                </Text>
            ) : null}

            <Pressable
                className="w-full max-w-md rounded-md py-2 items-center mt-6"
                onPress={() => router.back()}
            >
                <Text className="text-muted-text text-xs">Back</Text>
            </Pressable>
        </View>
    );
}