import { useState } from "react";
import { Pressable, Text, View } from "react-native";
import { FileDown, ShieldCheck } from "lucide-react";
import { downloadRecoveryFile } from "@/src/lib/auth/recovery-file";

/**
 * The mandatory recovery interstitial, shown once during vault creation.
 *
 * This screen **cannot be skipped**. There is no "remind me later" and no
 * countdown: the Continue button stays disabled until the "Save my recovery
 * file" checkbox is ticked, and that checkbox is the only way through. A
 * readability timeout would be theatre — it would let a user past a gate whose
 * entire purpose is that they do not skip it.
 *
 * The recovery key is issued as a **file**, not as text on a screen. A key on
 * screen has to be transcribed, and transcription is where recovery keys die;
 * a file can be stored, moved to wherever the rest of the household's
 * documents live, printed from there, and read back by this app on the day it
 * is needed. So the key is never rendered here, and never goes to the clipboard
 * — the only copies that exist are the file the user saves and the server's
 * encrypted envelope.
 *
 * **Pressing Continue is what creates the vault.** Registration happens after
 * this screen, not before it, so that a `vault` row can never exist without the
 * user already holding the file that opens it. The screen says so, because a
 * user who closes the tab here should know they have lost nothing at all —
 * that reassurance is only true because of the ordering, and it stops being
 * true the moment anyone moves the register call back to the front.
 *
 * The file is offered ONCE per attempt. There is deliberately no way to see it
 * again afterwards: Settings can only *rotate* it, never replay it. Someone who
 * gets past the lock screen could otherwise read the one credential that
 * bypasses it.
 *
 * On a failed commit the prepared material is deliberately kept, so pressing
 * Continue again re-uses the SAME vault id and the SAME recovery key — the file
 * already in the user's Downloads folder has to stay valid, or a flaky network
 * would quietly orphan it.
 */
export function RecoveryKeyInterstitial({
    recoveryKey,
    vaultId,
    name,
    onContinue,
    busy,
    error,
}: {
    /** `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` — never rendered, only written to a file. */
    recoveryKey: string;
    vaultId: string;
    /** User-chosen display name, shown here and written into the PDF. */
    name?: string;
    onContinue: () => void;
    busy?: boolean;
    /** Set when the commit failed. Continue stays enabled: the retry is safe. */
    error?: string | null;
}) {
    const [confirmed, setConfirmed] = useState(false);
    /** Set once a download has been asked for. */
    const [saved, setSaved] = useState(false);
    const [fileName, setFileName] = useState<string | null>(null);

    const payload = { vaultId, recoveryKey, name };

    const onDownload = () => {
        setFileName(downloadRecoveryFile(payload));
        setSaved(true);
    };

    /**
     * Ticking the box IS the save.
     *
     * Continue used to require a separate Download click *and* the checkbox,
     * which bought nothing: it never checked that a file reached the disk, only
     * that a click happened. Folding the download into the tick means the file
     * can never go un-offered, without asking the user for two gestures that
     * say the same thing — and it matches the rotation flow in Settings, where
     * the confirmation alone is the gate.
     *
     * The tick is a real user gesture, so the browser will honour the download
     * fired from it (the same reason `downloadRecoveryFile` refuses to fire
     * outside a click). Guarded on `saved` so an already-downloaded file is not
     * written a second time.
     */
    const onToggleConfirmed = () => {
        const next = !confirmed;
        setConfirmed(next);
        if (next && !saved) onDownload();
    };

    // A failed commit leaves the error on screen but keeps Continue available:
    // the retry re-uses the same prepared vault id and recovery key, so the file
    // already saved stays valid.
    const canContinue = confirmed && !busy;

    return (
        <View className="flex-1 bg-ground px-6 py-10">
            <View className="w-12 h-12 rounded-full bg-card items-center justify-center mb-4 border border-border">
                <ShieldCheck size={22} color="#7FD1A6" />
            </View>

            <Text className="text-primary-text text-xl font-bold mb-2">
                Save your recovery file
            </Text>
            <Text className="text-muted-text text-sm mb-6 leading-5">
                This is the only way back into this vault if you forget your master
                password or lose this device. It is a single PDF — keep it with your
                important documents, or print it from there. Nobody, including this
                server, can recover it for you.
            </Text>

            <Pressable
                accessibilityRole="button"
                className="w-full max-w-md rounded-xl bg-accent-line py-4 items-center flex-row justify-center"
                onPress={onDownload}
            >
                <FileDown size={18} color="#0b0d10" />
                <Text className="text-primary-text font-medium ml-2">
                    Download recovery file
                </Text>
            </Pressable>

            {fileName ? (
                <Text className="text-muted-text text-xs mt-4 mb-1 text-center">
                    Saved as <Text className="text-primary-text">{fileName}</Text>.
                </Text>
            ) : null}

            <Text className="text-muted-text text-xs mb-6 leading-4 mt-4">
                Or just tick the box below and the file downloads itself. Move it out
                of your Downloads folder — on most systems that folder is backed up
                and scanned automatically, and this file opens your vault on its own.
                It is offered once; if you lose it, you cannot have it back.
            </Text>

            {error ? (
                <Text className="text-red-400 text-xs mb-4 leading-4">{error}</Text>
            ) : null}

            <Pressable
                accessibilityRole="checkbox"
                accessibilityState={{ checked: confirmed }}
                className="flex-row items-center mb-6"
                onPress={onToggleConfirmed}
            >
                <View
                    className={`w-5 h-5 rounded border items-center justify-center mr-3 ${
                        confirmed ? "border-accent-line bg-accent" : "border-border-strong"
                    }`}
                >
                    {confirmed ? <Text className="text-xs text-primary-text">✓</Text> : null}
                </View>
                <Text className="text-primary-text text-sm">
                    Save my recovery file
                </Text>
            </Pressable>

            <Pressable
                className={`w-full rounded-lg py-3 items-center ${
                    canContinue ? "bg-accent-line" : "bg-surface"
                }`}
                onPress={onContinue}
                disabled={!canContinue}
            >
                <Text className={canContinue ? "text-primary-text font-medium" : "text-muted-text"}>
                    {busy ? "Creating your vault…" : "Create my vault"}
                </Text>
            </Pressable>

            <Text className="text-muted-text text-xs mt-4 text-center leading-4">
                Nothing has been uploaded yet. Your vault is created when you continue
                — if you close this tab now, there is nothing to undo.
            </Text>

            <Text className="text-muted-text text-xs mt-6 text-center">
                {name ? `${name} · ` : ""}Vault {vaultId.slice(0, 8)}…
            </Text>
        </View>
    );
}