import { useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";
import { useRouter } from "expo-router";
import { KeyRound } from "lucide-react";
import { useAppStore, switchVaultOpen, captureSelectionEpoch } from "@/src/lib/state";
import {
    abandonPendingRecovery,
    completeRecovery,
    describeRecoveryError,
    hasPendingRecovery,
    pendingRecoveryVaultId,
} from "@/src/lib/auth/flows/recover";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { upsertVaultId, upsertVaultVersion } from "@/src/lib/sqlite/web/services/client-state-service";
import { queryClient } from "@/src/lib/queries/client";
import { displayVaultName } from "@/src/lib/vault/name";

/**
 * Recovery step 2 of 2 — choose a new master password and open the vault.
 *
 * Reached only after step 1 proved the recovery file's key works. The recovered
 * vault key lives in the in-memory pending state (`lib/auth/flows/recover.ts`),
 * never in the URL and never on disk, so it is not sitting in browser history or
 * a referrer header between the two screens.
 *
 * Direct navigation (or a reload) lands here with no pending state — the vault
 * key did not survive — so it sends the user back to step 1 rather than failing
 * obscurely.
 */
export default function RecoverPassword() {
    useAuthGuard(["no_vault", "locked"]);
    const router = useRouter();
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    // Read once at mount: this screen is only reachable as the destination of a
    // completed step 1, and the state cannot appear later.
    const [ready] = useState(hasPendingRecovery);
    const vaultId = pendingRecoveryVaultId();

    // Note the deliberate ABSENCE of an unmount effect that wipes the pending
    // state. StrictMode is enabled at the root, and it mounts, unmounts, and
    // remounts every component once in development — an unmount cleanup would
    // abandon the attempt the user is standing in the middle of, leaving them on
    // a screen that can no longer succeed. Clearing is explicit instead:
    // `completeRecovery` clears in a `finally`, so success and terminal failure
    // are both covered, and "Start over" covers deliberate abandonment.

    const startOver = () => {
        abandonPendingRecovery();
        router.replace("/recover" as any);
    };

    const onComplete = async () => {
        if (newPassword !== confirmPassword) {
            setError("Passwords do not match.");
            return;
        }
        if (newPassword.length < 8) {
            setError("New master password must be at least 8 characters.");
            return;
        }
        setError(null);
        setBusy(true);

        const guard = captureSelectionEpoch();
        try {
            const result = await completeRecovery({ newPassword });

            if (!guard.stillCurrent()) {
                console.warn("Recovery discarded: selection changed while completing");
                return;
            }

            // Atomic install of selection + session + key + document + version.
            switchVaultOpen({
                requestedVaultId: result.session.vaultId,
                session: result.session,
                vaultKey: result.vaultKey,
                decryptedVault: result.decryptedVault,
                version: result.version,
                lockEpoch: result.lockEpoch,
            });

            await initSQLite(result.session.vaultId);
            await upsertVaultId(result.session.vaultId);
            await upsertVaultVersion(result.version);
            result.vaultKeyRaw.fill(0);

            queryClient.removeQueries({ queryKey: ["vault"] });
            router.replace("/home" as any);
        } catch (e) {
            console.warn("Recovery could not be completed", e);
            const message = describeRecoveryError(e);
            setError(message);
            if (!hasPendingRecovery()) {
                // The attempt is gone (server rejected it, or another tab
                // recovered first). Nothing typed here can succeed now, so clear
                // the fields and point the user at "Start over".
                setNewPassword("");
                setConfirmPassword("");
            }
            // Otherwise the failure was local — a confirmation typo or a
            // validation error — the server was never touched, and the user can
            // simply correct it and submit again.
        } finally {
            setBusy(false);
        }
    };

    if (!ready) {
        return (
            <View className="flex-1 items-center justify-center bg-ground px-6">
                <Text className="text-primary-text text-xl font-bold mb-2">
                    Start over
                </Text>
                <Text className="text-muted-text text-sm mb-6 text-center max-w-md leading-5">
                    This recovery attempt is no longer active. Open your recovery file
                    again to continue.
                </Text>
                <Pressable
                    className="w-full max-w-md rounded-lg bg-accent-line py-3 items-center"
                    onPress={startOver}
                >
                    <Text className="text-primary-text font-medium">Open recovery file</Text>
                </Pressable>
            </View>
        );
    }

    const canSubmit =
        newPassword.length >= 8 && newPassword === confirmPassword && !busy;

    return (
        <View className="flex-1 items-center justify-center bg-ground px-6 py-10">
            <View className="w-12 h-12 rounded-full bg-card items-center justify-center mb-4 border border-border">
                <KeyRound size={22} color="#7FD1A6" />
            </View>
            <Text className="text-primary-text text-xl font-bold mb-2">
                Choose a new master password
            </Text>
            <Text className="text-muted-text text-sm mb-6 text-center max-w-md leading-5">
                Step 2 of 2 — your recovery file is verified.
                {vaultId ? ` ${displayVaultName(vaultId)}` : ""}
            </Text>

            <TextInput
                className="w-full max-w-md rounded-md border border-border bg-surface px-3 py-2 mb-3 text-primary-text"
                placeholder="New master password (≥8 chars)"
                placeholderTextColor="#7E8590"
                secureTextEntry
                value={newPassword}
                onChangeText={setNewPassword}
            />
            <TextInput
                className="w-full max-w-md rounded-md border border-border bg-surface px-3 py-2 mb-4 text-primary-text"
                placeholder="Confirm new password"
                placeholderTextColor="#7E8590"
                secureTextEntry
                value={confirmPassword}
                onChangeText={setConfirmPassword}
                onSubmitEditing={onComplete}
            />

            <Pressable
                className={`w-full max-w-md rounded-lg py-3 items-center ${
                    canSubmit ? "bg-accent-line" : "bg-surface"
                }`}
                onPress={onComplete}
                disabled={!canSubmit}
            >
                <Text
                    className={canSubmit ? "text-primary-text font-medium" : "text-muted-text"}
                >
                    {busy ? "Recovering…" : "Recover this vault"}
                </Text>
            </Pressable>

            {error ? (
                <Text className="text-red-400 mt-3 text-center text-sm max-w-md">{error}</Text>
            ) : null}

            <Pressable
                className="w-full max-w-md rounded-md py-2 items-center mt-6"
                onPress={startOver}
            >
                <Text className="text-muted-text text-xs">Start over</Text>
            </Pressable>
        </View>
    );
}