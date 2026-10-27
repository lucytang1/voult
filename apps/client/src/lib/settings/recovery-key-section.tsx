import { useState } from "react";
import { Pressable, Text, View } from "react-native";
import { FileDown, KeyRound } from "lucide-react";
import { useAppStore } from "@/src/lib/state";
import { useGetCryptoParams } from "@/src/lib/queries/cryptoParams/query";
import { useRecoveryChallengeMutation, useRecoveryRegenerateMutation, useRecoveryUnlockMutation } from "@/src/lib/queries/recovery/mutations";
import { describeRecoveryError } from "@/src/lib/auth/flows/recover";
import { downloadRecoveryFile, readRecoveryFile } from "@/src/lib/auth/recovery-file";
import { RecoveryFilePicker } from "@/src/lib/components/recovery-file-picker";
import {
    b64,
    newSaltB64,
    computeRecoveryVerifier,
    computeRecoveryProof,
    deriveRecoveryWrapKey,
    formatRecoveryKey,
    generateRecoverySecret,
    parseRecoveryKey,
    recoveryAad,
    unwrapKeyBytes,
    wrapKeyBytes,
} from "@/src/lib/crypto/index.web";

/**
 * Recovery key management. Deliberately ROTATE-ONLY.
 *
 * There is no "enable" and no "disable". Recovery is a mandatory property of
 * every vault, created with it; the only operation this section offers is
 * replacing the file — for the case that matters, a lost or compromised copy.
 *
 * Rotating proves possession of the CURRENT file before it will issue a new
 * one. That is the point: without it, anyone who could get past the lock screen
 * could rotate the key and lock the real owner out permanently. It also means a
 * copy that leaked is genuinely revoked the moment the owner rotates.
 *
 * That proof is a file selection, exactly as at first-time recovery. Rotating
 * is the one moment the user must produce the artifact they saved months ago,
 * and making them retype 32 characters to do it would be a recovery flow
 * failing at the last step.
 *
 * The new file is offered once, exactly like the create-flow interstitial, and
 * the old one stops working immediately.
 */
export function RecoveryKeySection() {
    const vaultId = useAppStore((s) =>
        s.vault.status === "no_vault" ? null : s.vault.vaultId,
    );
    const unlocked = useAppStore((s) => s.vault.status === "unlocked");
    const vaultName = useAppStore((s) => s.decryptedVault?.name);
    const [stage, setStage] = useState<"idle" | "proving" | "showing">("idle");
    const [newKey, setNewKey] = useState<string | null>(null);
    const [confirmed, setConfirmed] = useState(false);
    const [fileName, setFileName] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    const paramsQuery = useGetCryptoParams(vaultId ?? "", !!vaultId && unlocked);
    const challengeMutation = useRecoveryChallengeMutation();
    const unlockMutation = useRecoveryUnlockMutation();
    const regenerateMutation = useRecoveryRegenerateMutation();

    if (!vaultId) return null;

    const hasRecovery = paramsQuery.data?.has_recovery === true;

    const startRotation = () => {
        setError(null);
        setNewKey(null);
        setConfirmed(false);
        setFileName(null);
        setStage("proving");
    };

    const cancel = () => {
        setStage("idle");
        setNewKey(null);
        setConfirmed(false);
        setFileName(null);
        setError(null);
        challengeMutation.reset();
        regenerateMutation.reset();
    };

    /**
     * Rotate. Takes the CURRENT recovery file, proves it, and hands the server
     * a new envelope — the raw vault key is wrapped locally and only the
     * ciphertext crosses the wire, as everywhere else.
     */
    const rotate = async (file: File) => {
        setError(null);
        setBusy(true);
        try {
            const params = paramsQuery.data;
            if (!params?.recovery_salt) throw new Error("RECOVERY_NOT_ENABLED");

            const current = await readRecoveryFile(file);
            // The file is the credential, and it names its own vault. Checking
            // the id here turns "you picked the wrong file" into a sentence
            // rather than the server's deliberately undifferentiated 401 — and
            // a vault id is not a secret, it is printed on the same page.
            if (current.vaultId !== vaultId) {
                throw new Error("RECOVERY_FILE_OTHER_VAULT");
            }
            setFileName(file.name);

            const currentSecret = parseRecoveryKey(current.recoveryKey);
            const currentK = await deriveRecoveryWrapKey(
                currentSecret,
                params.recovery_salt,
            );

            // Prove possession of the key being replaced, then take the existing
            // envelope back out of the server.
            const { selector, challenge } = await challengeMutation.mutateAsync({
                vault_id: vaultId,
            });
            const currentVerifier = await computeRecoveryVerifier(
                currentSecret,
                params.recovery_salt,
            );
            const proof = await computeRecoveryProof(currentVerifier, vaultId, challenge);

            const released = await unlockMutation.mutateAsync({
                vault_id: vaultId,
                selector,
                proof: b64(proof),
            });

            // The raw vault key comes from unwrapping the CURRENT recovery
            // envelope — the very thing the user just proved they can do. This is
            // why the vault key never has to be made extractable: the app holds
            // it as a non-extractable CryptoKey, and rotation never needs it in
            // the clear.
            let vaultKeyRaw: Uint8Array;
            try {
                vaultKeyRaw = await unwrapKeyBytes(
                    released.recovery_wrap,
                    released.recovery_wrap_iv,
                    currentK,
                    recoveryAad(vaultId),
                );
            } catch {
                throw new Error("RECOVERY_FAILED");
            }

            // New material, generated locally. The new secret never leaves here.
            const newSecret = generateRecoverySecret();
            const newSalt = newSaltB64();
            const newK = await deriveRecoveryWrapKey(newSecret, newSalt);
            const newVerifier = await computeRecoveryVerifier(newSecret, newSalt);

            // Rule R1: wrap the raw vault key directly, bound to this vault.
            const envelope = await wrapKeyBytes(vaultKeyRaw, newK, recoveryAad(vaultId));

            await regenerateMutation.mutateAsync({
                vault_id: vaultId,
                selector,
                proof: b64(proof),
                new_recovery_verifier: b64(newVerifier),
                new_recovery_salt: newSalt,
                new_recovery_wrap: b64(envelope.cipher),
                new_recovery_wrap_iv: b64(envelope.iv),
            });

            // Render for display FIRST, then wipe. After this the only copy is
            // the file the user saves next.
            const newKeyText = formatRecoveryKey(newSecret);
            newSecret.fill(0);
            vaultKeyRaw.fill(0);

            setNewKey(newKeyText);
            setStage("showing");
        } catch (e) {
            console.warn("Recovery file rotation failed", e);
            setError(describeRecoveryError(e));
        } finally {
            setBusy(false);
        }
    };

    if (stage === "showing" && newKey) {
        const payload = { vaultId, recoveryKey: newKey, name: vaultName };
        return (
            <View className="mt-6 mb-4 rounded-2xl bg-surface1 overflow-hidden p-5">
                <Text className="mb-2 text-sm font-semibold text-primary-text">
                    Your new recovery file
                </Text>
                <Text className="mb-4 text-xs text-muted-text">
                    The previous file no longer works. This one is offered once and
                    cannot be generated again.
                </Text>

                <Pressable
                    accessibilityRole="button"
                    className="w-full rounded-lg bg-accent-line py-3 items-center flex-row justify-center"
                    onPress={() => setFileName(downloadRecoveryFile(payload))}
                >
                    <FileDown size={16} color="#0b0d10" />
                    <Text className="text-primary-text font-medium text-sm ml-2">
                        Download recovery file
                    </Text>
                </Pressable>

                {fileName ? (
                    <Text className="text-muted-text text-xs mt-3">
                        Saved as <Text className="text-primary-text">{fileName}</Text>.
                    </Text>
                ) : null}

                <Pressable
                    accessibilityRole="checkbox"
                    accessibilityState={{ checked: confirmed }}
                    className="flex-row items-center mt-5"
                    onPress={() => setConfirmed((v) => !v)}
                >
                    <View
                        className={`w-5 h-5 rounded border items-center justify-center mr-3 ${
                            confirmed ? "border-accent-line bg-accent" : "border-hairline-accent"
                        }`}
                    >
                        {confirmed ? <Text className="text-xs text-primary-text">✓</Text> : null}
                    </View>
                    <Text className="text-primary-text text-sm">
                        I have saved my new recovery file
                    </Text>
                </Pressable>

                <Pressable
                    className={`w-full rounded-lg py-3 items-center mt-3 ${
                        confirmed ? "bg-accent-line" : "bg-surface"
                    }`}
                    disabled={!confirmed}
                    onPress={() => {
                        setNewKey(null);
                        setStage("idle");
                        setConfirmed(false);
                        setFileName(null);
                    }}
                >
                    <Text
                        className={
                            confirmed ? "text-primary-text font-medium" : "text-muted-text"
                        }
                    >
                        Done
                    </Text>
                </Pressable>
            </View>
        );
    }

    if (stage === "proving") {
        return (
            <View className="mt-6 mb-4 rounded-2xl bg-surface1 overflow-hidden p-5">
                <Text className="mb-2 text-sm font-semibold text-primary-text">
                    Rotate recovery file
                </Text>
                <Text className="mb-4 text-xs text-muted-text">
                    Open the recovery file you saved for this vault to confirm it is
                    yours. The previous file stops working the moment the new one is
                    saved.
                </Text>

                <RecoveryFilePicker
                    onFile={rotate}
                    busy={busy}
                    title={busy ? "Checking file…" : "Choose your current recovery file"}
                    hint="the voult-recovery-….pdf that opens THIS vault"
                />

                {error ? <Text className="mt-3 text-xs text-red-400">{error}</Text> : null}
                {fileName && !error ? (
                    <Text className="mt-3 text-xs text-muted-text">Using {fileName}</Text>
                ) : null}

                <Pressable
                    className="mt-4 w-full rounded-lg bg-surface border border-hairline-accent px-4 py-2.5 items-center"
                    onPress={cancel}
                    disabled={busy}
                >
                    <Text className="text-sm text-primary-text">Cancel</Text>
                </Pressable>
            </View>
        );
    }

    return (
        <View className="mt-6 mb-4 rounded-2xl bg-surface1 overflow-hidden p-5">
            <View className="mb-2 flex-row items-center">
                <KeyRound size={16} color="#a1a1aa" />
                <Text className="ml-2 text-sm font-semibold text-primary-text">
                    Recovery file
                </Text>
            </View>
            <Text className="mb-3 text-xs text-muted-text">
                {hasRecovery
                    ? "Recovery is active — this vault can be opened with your recovery file if you forget your master password. The file itself is never generated again; rotate it if your copy is lost or exposed."
                    : "Checking recovery status…"}
            </Text>
            <Pressable
                className="self-start rounded-lg bg-accent border border-hairline-accent px-4 py-2.5"
                onPress={startRotation}
                disabled={!hasRecovery}
            >
                <Text className="text-sm text-primary-text">Rotate recovery file</Text>
            </Pressable>
        </View>
    );
}