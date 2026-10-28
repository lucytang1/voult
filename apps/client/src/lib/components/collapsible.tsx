import { useState, type ReactNode } from "react";
import { Pressable, Text, View } from "react-native";
import { ChevronDown, ChevronRight } from "lucide-react";

/**
 * Disclosure block for detail a user asks for rather than gets by default.
 *
 * Collapsed by default and controlled locally: none of the current callers need
 * to know whether it is open, and keeping it uncontrolled means a parent
 * re-render (every poll tick on the backup pane) cannot collapse it under the
 * user.
 */
export function Collapsible({
  title,
  children,
  defaultOpen = false,
}: {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const Chevron = open ? ChevronDown : ChevronRight;

  return (
    <View>
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ expanded: open }}
        accessibilityLabel={title}
        onPress={() => setOpen((value) => !value)}
        className="flex-row items-center self-start rounded-md py-1.5"
      >
        <Chevron size={14} className="text-muted-text" />
        <Text className="ml-1 text-xs font-medium text-muted-text">{title}</Text>
      </Pressable>
      {open && <View className="mt-2">{children}</View>}
    </View>
  );
}
