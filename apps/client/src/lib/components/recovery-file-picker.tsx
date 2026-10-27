import { useCallback, useEffect, useState } from "react";
import { Pressable, Text, View } from "react-native";
import { FileUp } from "lucide-react";
import { firstPdfIn, pickRecoveryFile } from "@/src/lib/auth/recovery-file";

/**
 * Chooses a recovery file, by click or by drop.
 *
 * Shared by every screen that needs one — first-time recovery and key rotation
 * both ask for the same artifact — so the file rules, the accept filter, and
 * the drop behaviour cannot drift between them.
 *
 * This component hands the screen a raw `File` and nothing else. Parsing is the
 * caller's business: it needs the payload AND a failure message, and the two
 * screens that use this want to report failures differently.
 *
 * Drag-and-drop is wired at the window, not on the drop target. A file dropped
 * anywhere else on the page would otherwise navigate the tab away from the
 * recovery attempt and lose the vault key it was holding in memory — so the
 * window listeners exist as much to swallow those drops as to catch the good
 * ones.
 */
export function RecoveryFilePicker({
    onFile,
    busy = false,
    disabled = false,
    title = "Choose recovery file",
    hint = "or drop the PDF here — the one you saved when this vault was created",
}: {
    /** Receives the chosen file, already narrowed to a PDF when possible. */
    onFile: (file: File) => void;
    busy?: boolean;
    disabled?: boolean;
    title?: string;
    hint?: string;
}) {
    const [dragging, setDragging] = useState(false);

    const onChoose = useCallback(async () => {
        try {
            const file = await pickRecoveryFile();
            if (file) onFile(file);
        } catch {
            // No DOM, or the browser refused to open a chooser. The screen will
            // still be here; this is not worth an error message.
        }
    }, [onFile]);

    useEffect(() => {
        if (typeof window === "undefined") return;

        // `dragenter`/`dragleave` fire for every element the pointer crosses, so
        // the counter tracks nesting instead of toggling on every crossing —
        // otherwise the highlight flickers off the moment the cursor moves
        // within the target.
        let depth = 0;
        const onEnter = (e: DragEvent) => {
            if (!e.dataTransfer?.types.includes("Files")) return;
            e.preventDefault();
            depth += 1;
            setDragging(true);
        };
        const onLeave = (e: DragEvent) => {
            if (!e.dataTransfer?.types.includes("Files")) return;
            e.preventDefault();
            depth = Math.max(0, depth - 1);
            if (depth === 0) setDragging(false);
        };
        const onOver = (e: DragEvent) => {
            if (!e.dataTransfer?.types.includes("Files")) return;
            // Required, or the browser opens the file itself and the tab goes.
            e.preventDefault();
            e.dataTransfer.dropEffect = "copy";
        };
        const onDrop = (e: DragEvent) => {
            if (!e.dataTransfer?.types.includes("Files")) return;
            e.preventDefault();
            depth = 0;
            setDragging(false);
            const file = firstPdfIn(e.dataTransfer.files);
            if (file) onFile(file);
        };

        window.addEventListener("dragenter", onEnter);
        window.addEventListener("dragleave", onLeave);
        window.addEventListener("dragover", onOver);
        window.addEventListener("drop", onDrop);
        return () => {
            window.removeEventListener("dragenter", onEnter);
            window.removeEventListener("dragleave", onLeave);
            window.removeEventListener("dragover", onOver);
            window.removeEventListener("drop", onDrop);
        };
    }, [onFile]);

    const idle = !busy && !disabled;

    return (
        <Pressable
            accessibilityRole="button"
            accessibilityLabel={title}
            accessibilityHint={hint}
            accessibilityState={{ disabled: !idle, busy }}
            className={`w-full max-w-md rounded-xl border-2 border-dashed px-6 py-10 items-center ${
                dragging ? "border-accent-line bg-card" : "border-border bg-surface"
            }`}
            onPress={idle ? onChoose : undefined}
            disabled={!idle}
        >
            <FileUp size={26} color={dragging ? "#7FD1A6" : "#7E8590"} />
            <Text className="text-primary-text text-sm font-medium mt-3 mb-1">
                {busy ? "Reading file…" : title}
            </Text>
            <Text className="text-muted-text text-xs text-center leading-4">{hint}</Text>
        </Pressable>
    );
}