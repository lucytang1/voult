import { useRef, useState } from "react";
import { Pressable, Text, View } from "react-native";
import { Folder, MoreHorizontal } from "lucide-react";
import { FolderActionsMenu } from "./folder-actions-menu";
import type { Folder as FolderType } from "@voult/vault-core";

export function FolderList({
  folders,
  selectedFolderId,
  counts,
  onSelect,
  onCreate,
  onRename,
  onDelete,
}: {
  folders: FolderType[];
  selectedFolderId: string | null; // null = "All items"
  counts: { all: number; unfiled: number; byId: Record<string, number> };
  onSelect: (id: string | null) => void;
  onCreate: () => void;
  onRename: (folder: FolderType) => void;
  onDelete: (folder: FolderType) => void;
}) {
  // The overflow menu anchors under the button that opened it, so its position
  // is measured from the button rather than guessed.
  const [menu, setMenu] = useState<{ folder: FolderType; x: number; y: number } | null>(null);
  const buttonRefs = useRef<Record<string, View | null>>({});

  const openMenu = (folder: FolderType) => {
    const node = buttonRefs.current[folder.id];
    if (!node || typeof node.measureInWindow !== "function") {
      // No measurable node (or a platform without it): fall back to a fixed spot
      // near the top of the folder list rather than opening nowhere.
      setMenu({ folder, x: 12, y: 120 });
      return;
    }
    node.measureInWindow((x, y, width, height) => {
      // Open to the RIGHT of the button, and keep the whole panel on screen.
      const panelWidth = 176;
      const maxX = Math.max(8, window.innerWidth - panelWidth - 8);
      setMenu({
        folder,
        x: Math.min(x + width + 8, maxX),
        y: y + height + 4,
      });
    });
  };

  return (
    <View className="px-2">
      {/* All items — a view over the whole vault, not a folder. */}
      <Pressable
        className={`flex-row items-center px-3 py-2 rounded-lg mb-1 ${
          selectedFolderId === null ? "bg-surface" : "hover:bg-surface2"
        }`}
        onPress={() => onSelect(null)}
      >
        <Folder size={16} color="#fff" style={{ marginRight: 12 }} />
        <View className="flex-1">
          <Text className="text-primary-text text-sm font-medium">All items</Text>
          <Text className="text-muted-text text-xs">{counts.all} items</Text>
        </View>
      </Pressable>

      {/* Folders */}
      <View className="px-4 py-3 flex-row justify-between items-center">
        <Text className="text-xs font-semibold text-muted-text uppercase tracking-wider">Folders</Text>
        <Pressable onPress={onCreate} accessibilityLabel="New folder">
          <Text className="text-muted-text hover:text-primary-text text-lg">+</Text>
        </Pressable>
      </View>

      {folders.map((f) => (
        <Pressable
          key={f.id}
          className={`group flex-row items-center px-3 py-2 rounded-lg mb-1 ${
            selectedFolderId === f.id ? "bg-surface" : "hover:bg-surface2"
          }`}
          onPress={() => onSelect(f.id)}
        >
          <Folder size={16} color="#9ca3af" style={{ marginRight: 12 }} />
          <View className="flex-1">
            <Text className="text-primary-text text-sm font-medium">{f.name}</Text>
            <Text className="text-muted-text text-xs">{counts.byId[f.id] ?? 0} items</Text>
          </View>
          <Pressable
            ref={(node) => {
              buttonRefs.current[f.id] = node;
            }}
            onPress={(event) => {
              // The row itself is pressable; without this the kebab press would
              // also select the folder.
              event?.stopPropagation?.();
              openMenu(f);
            }}
            accessibilityLabel={`${f.name} options`}
            hitSlop={8}
          >
            <MoreHorizontal size={15} color="#9ca3af" />
          </Pressable>
        </Pressable>
      ))}

      {counts.unfiled > 0 && (
        <Pressable
          className={`flex-row items-center px-3 py-2 rounded-lg mb-1 ${
            selectedFolderId === "unfiled" ? "bg-surface" : "hover:bg-surface2"
          }`}
          onPress={() => onSelect("unfiled")}
        >
          <Folder size={16} color="#9ca3af" style={{ marginRight: 12 }} />
          <View className="flex-1">
            <Text className="text-primary-text text-sm font-medium">Unfiled</Text>
            <Text className="text-muted-text text-xs">{counts.unfiled} items</Text>
          </View>
        </Pressable>
      )}

      <FolderActionsMenu
        folder={menu?.folder ?? null}
        position={{ x: menu?.x ?? 0, y: menu?.y ?? 0 }}
        onClose={() => setMenu(null)}
        onRename={(f) => {
          setMenu(null);
          onRename(f);
        }}
        onDelete={(f) => {
          setMenu(null);
          onDelete(f);
        }}
      />
    </View>
  );
}
