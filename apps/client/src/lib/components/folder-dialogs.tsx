import { useEffect, useRef, useState } from "react";
import { Modal, Pressable, Text, TextInput, View } from "react-native";
import { normalizeFolderName, MAX_FOLDER_NAME_LENGTH } from "@voult/vault-core";
import type { Folder } from "@voult/vault-core";
import { TextField } from "./text-field";

export function CreateFolderDialog({
  visible,
  folders,
  onClose,
  onCreate,
}: {
  visible: boolean;
  folders: Folder[];
  onClose: () => void;
  onCreate: (name: string) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<TextInput>(null);

  useEffect(() => {
    if (visible) {
      setName("");
      setError(null);
      const t = setTimeout(() => inputRef.current?.focus(), 100);
      return () => clearTimeout(t);
    }
  }, [visible]);

  const normalized = normalizeFolderName(name);
  const dup =
    normalized !== null &&
    folders.some((f) => f.name.toLowerCase() === normalized.toLowerCase());
  const tooLong = name.replace(/\s+/g, " ").trim().length > MAX_FOLDER_NAME_LENGTH;

  const submit = async () => {
    if (!normalized) {
      setError("Enter a name between 1 and 48 characters.");
      return;
    }
    if (dup) {
      setError("A folder with that name already exists.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onCreate(normalized);
      setName("");
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create folder.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <View className="flex-1 bg-black/60 items-center justify-center">
        <View className="bg-surface1 rounded-xl p-6 w-80 border border-hairline-accent">
          <Text className="text-xl font-bold text-primary-text mb-4">New folder</Text>
          <TextField
            ref={inputRef}
            className="mb-2"
            placeholder="Folder name"
            value={name}
            onChangeText={(t) => {
              setName(t);
              setError(null);
            }}
            onSubmitEditing={submit}
          />
          <Text className={`text-xs ${tooLong ? "text-red-400" : "text-muted-text"}`}>
            {tooLong
              ? `Names can be up to ${MAX_FOLDER_NAME_LENGTH} characters.`
              : `${normalized?.length ?? 0}/${MAX_FOLDER_NAME_LENGTH}`}
          </Text>
          {error ? <Text className="text-red-400 text-xs mt-2">{error}</Text> : null}
          <View className="flex-row justify-end space-x-2 mt-4">
            <Pressable className="px-4 py-2 rounded-lg" onPress={onClose}>
              <Text className="text-muted-text">Cancel</Text>
            </Pressable>
            <Pressable
              className={`px-4 py-2 rounded-lg ${
                normalized && !dup && !busy ? "bg-accent border border-hairline-accent" : "bg-surface border border-border"
              }`}
              onPress={submit}
              disabled={!normalized || dup || busy}
            >
              <Text className={normalized && !dup && !busy ? "text-primary-text font-medium" : "text-muted-text"}>
                {busy ? "Creating…" : "Create"}
              </Text>
            </Pressable>
          </View>
        </View>
      </View>
    </Modal>
  );
}

export function RenameFolderDialog({
  visible,
  folder,
  folders,
  onClose,
  onRename,
}: {
  visible: boolean;
  folder: Folder | null;
  folders: Folder[];
  onClose: () => void;
  onRename: (id: string, name: string) => Promise<void>;
}) {
  const [name, setName] = useState(folder?.name ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<TextInput>(null);

  useEffect(() => {
    if (visible) {
      setName(folder?.name ?? "");
      setError(null);
      const t = setTimeout(() => inputRef.current?.focus(), 100);
      return () => clearTimeout(t);
    }
  }, [visible, folder?.id]);

  const normalized = normalizeFolderName(name);
  const dup =
    normalized !== null &&
    folders.some((f) => f.id !== folder?.id && f.name.toLowerCase() === normalized.toLowerCase());

  const submit = async () => {
    if (!folder) return;
    if (!normalized) {
      setError("Enter a name between 1 and 48 characters.");
      return;
    }
    if (dup) {
      setError("A folder with that name already exists.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onRename(folder.id, normalized);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not rename folder.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <View className="flex-1 bg-black/60 items-center justify-center">
        <View className="bg-surface1 rounded-xl p-6 w-80 border border-hairline-accent">
          <Text className="text-xl font-bold text-primary-text mb-4">Rename folder</Text>
          <TextField
            ref={inputRef}
            className="mb-2"
            placeholder="Folder name"
            value={name}
            onChangeText={(t) => {
              setName(t);
              setError(null);
            }}
            onSubmitEditing={submit}
          />
          {error ? <Text className="text-red-400 text-xs mt-2">{error}</Text> : null}
          <View className="flex-row justify-end space-x-2 mt-4">
            <Pressable className="px-4 py-2 rounded-lg" onPress={onClose}>
              <Text className="text-muted-text">Cancel</Text>
            </Pressable>
            <Pressable
              className={`px-4 py-2 rounded-lg ${
                normalized && !dup && !busy ? "bg-accent border border-hairline-accent" : "bg-surface border border-border"
              }`}
              onPress={submit}
              disabled={!normalized || dup || busy}
            >
              <Text className={normalized && !dup && !busy ? "text-primary-text font-medium" : "text-muted-text"}>
                {busy ? "Saving…" : "Save"}
              </Text>
            </Pressable>
          </View>
        </View>
      </View>
    </Modal>
  );
}

export function DeleteFolderDialog({
  visible,
  folder,
  itemCount,
  onClose,
  onDelete,
}: {
  visible: boolean;
  folder: Folder | null;
  itemCount: number;
  onClose: () => void;
  onDelete: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onDelete();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not delete folder.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <View className="flex-1 bg-black/60 items-center justify-center">
        <View className="bg-surface1 rounded-xl p-6 w-80 border border-hairline-accent">
          <Text className="text-xl font-bold text-primary-text mb-2">Delete folder</Text>
          <Text className="text-muted-text mb-6">
            Delete &ldquo;{folder?.name}&rdquo;? This also deletes {itemCount} password
            {itemCount === 1 ? "" : "s"} in it. This cannot be undone.
          </Text>
          {error ? <Text className="text-red-400 text-xs mb-3">{error}</Text> : null}
          <View className="flex-row justify-end space-x-2">
            <Pressable className="px-4 py-2 rounded-lg" onPress={onClose}>
              <Text className="text-muted-text">Cancel</Text>
            </Pressable>
            <Pressable
              className="px-4 py-2 bg-red-600 rounded-lg"
              onPress={submit}
              disabled={busy}
            >
              <Text className="text-primary-text font-medium">{busy ? "Deleting…" : "Delete"}</Text>
            </Pressable>
          </View>
        </View>
      </View>
    </Modal>
  );
}