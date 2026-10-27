import { Modal, Pressable, Text, View } from "react-native";
import { Pencil, Trash2 } from "lucide-react";
import type { Folder } from "@voult/vault-core";

/**
 * Per-folder overflow menu (the "hamburger"). Rendered in a transparent Modal so
 * the backdrop dismisses it and the panel can float above the sidebar.
 */
export function FolderActionsMenu({
  folder,
  position,
  onClose,
  onRename,
  onDelete,
}: {
  folder: Folder | null;
  position: { x: number; y: number };
  onClose: () => void;
  onRename: (folder: Folder) => void;
  onDelete: (folder: Folder) => void;
}) {
  return (
    <Modal visible={!!folder} transparent animationType="fade" onRequestClose={onClose}>
      {/* Backdrop: tapping anywhere else dismisses the menu. */}
      <Pressable
        style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0 }}
        onPress={onClose}
        accessibilityLabel="Close menu"
      />
      {/* The panel is only mounted while a folder is set: the modal fades out
          over ~250ms, and an unmounted panel would flash at 0,0 on the way out. */}
      {folder && (
        <View
          style={{ position: "absolute", left: position.x, top: position.y }}
          className="w-44 rounded-lg border border-hairline-accent bg-surface1 py-1"
        >
          <Pressable
            className="flex-row items-center px-3 py-2 hover:bg-surface2"
            onPress={() => onRename(folder)}
          >
            <Pencil size={13} color="#9ca3af" style={{ marginRight: 10 }} />
            <Text className="text-primary-text text-sm">Edit</Text>
          </Pressable>
          <Pressable
            className="flex-row items-center px-3 py-2 hover:bg-surface2"
            onPress={() => onDelete(folder)}
          >
            <Trash2 size={13} color="#f87171" style={{ marginRight: 10 }} />
            <Text className="text-red-400 text-sm">Delete</Text>
          </Pressable>
        </View>
      )}
    </Modal>
  );
}
