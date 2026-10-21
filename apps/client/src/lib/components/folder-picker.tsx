import { Pressable, Text, View } from "react-native";
import type { Folder } from "@voult/vault-core";

/**
 * Inline folder picker: a vertical list of selectable rows. Used by the add and
 * edit modals. "Unfiled" is intentionally not a target — it only exists for
 * items whose folder disappeared, and those get moved into a real folder by
 * picking one here.
 */
export function FolderPicker({
  folders,
  value,
  onChange,
}: {
  folders: Folder[];
  value: string | null;
  onChange: (id: string) => void;
}) {
  if (folders.length === 0) {
    return (
      <Text className="text-muted-text text-xs">
        No folders yet. Create one from the sidebar.
      </Text>
    );
  }
  return (
    <View className="gap-1">
      {folders.map((f) => {
        const active = f.id === value;
        return (
          <Pressable
            key={f.id}
            onPress={() => onChange(f.id)}
            className={`flex-row items-center px-3 py-2 rounded-lg ${
              active ? "bg-accent-line/20 border border-accent-line/40" : "bg-surface hover:bg-surface2"
            }`}
          >
            <Text className={active ? "text-primary-text font-medium" : "text-muted-text"}>{f.name}</Text>
          </Pressable>
        );
      })}
    </View>
  );
}