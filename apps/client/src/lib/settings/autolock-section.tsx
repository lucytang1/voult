import { useState } from "react";
import { Pressable, Text, View } from "react-native";
import { Lock, Monitor, Puzzle, type LucideIcon } from "lucide-react";
import {
  AUTOLOCK_CHOICES,
  describeAutolock,
  getExtensionAutolockMinutes,
  getWebAutolockMinutes,
  setExtensionAutolockMinutes,
  setWebAutolockMinutes,
} from "./index";

/**
 * Settings > Security > Autolock.
 *
 * Both timers mean the same thing on their own surface — "lock me after this
 * much inactivity" — but they are enforced by different processes and are
 * deliberately independent values:
 *
 *  - Web app: enforced here, by useAutolock() in the root layout.
 *  - Extension: enforced by the extension's own idle alarm against
 *    `voult.lockTimeoutMinutes` in chrome.storage.local. This app cannot write
 *    that storage, so the value below records the user's intent and is not yet
 *    delivered — see the footnote. Wiring it needs a per-vault settings record
 *    on the server that the extension pulls on its next session check.
 *
 * Note that either timer firing also locks the *other* surface: both publish
 * via POST /api/lock, which bumps the shared server `lock_epoch`. Separate
 * values mean separate idle thresholds, not isolated locks.
 */

function useAutolockValue(read: () => number, write: (minutes: number) => void) {
  // Read once on mount: the stored value is the source of truth, and the
  // watchdog re-reads it every tick so changes apply without a reload.
  const [minutes, setMinutes] = useState(read);
  const choose = (next: number) => {
    write(next);
    setMinutes(next);
  };
  return [minutes, choose] as const;
}

interface TimerRowProps {
  icon: LucideIcon;
  label: string;
  description: string;
  minutes: number;
  onChange: (minutes: number) => void;
  footnote?: string;
}

function TimerRow({ icon: Icon, label, description, minutes, onChange, footnote }: TimerRowProps) {
  return (
    <View className="border-t-[0.1px] border-hairline py-5 first:border-t-0 first:pt-0">
      <View className="mb-1 flex-row items-center">
        <Icon size={16} color="#a1a1aa" />
        <Text className="ml-2 text-sm font-semibold text-primary-text">{label}</Text>
        <Text className="ml-auto text-xs text-muted-text">Currently {describeAutolock(minutes)}</Text>
      </View>
      <Text className="mb-3 text-sm text-muted-text">{description}</Text>

      <View className="flex-row flex-wrap gap-2">
        {AUTOLOCK_CHOICES.map((choice) => {
          const active = choice.minutes === minutes;
          return (
            <Pressable
              key={choice.minutes}
              accessibilityRole="radio"
              accessibilityState={{ selected: active }}
              accessibilityLabel={`${label}: lock after ${choice.label}`}
              onPress={() => onChange(choice.minutes)}
              className={`rounded-lg border px-3 py-1.5 ${
                active
                  ? "border-accent-line bg-accent-line/20"
                  : "border-hairline-accent bg-surface hover:border-hairline-accent"
              }`}
            >
              <Text className={`text-xs ${active ? "font-medium text-primary-text" : "text-muted-text"}`}>
                {choice.label}
              </Text>
            </Pressable>
          );
        })}
      </View>

      {minutes <= 0 && (
        <Text className="mt-3 text-xs text-yellow-400">
          {label} will stay unlocked until you lock it manually. Locking also stops surviving a
          page reload.
        </Text>
      )}
      {footnote && <Text className="mt-3 text-xs text-muted-text">{footnote}</Text>}
    </View>
  );
}

export function AutolockSection() {
  const [webMinutes, setWebMinutes] = useAutolockValue(getWebAutolockMinutes, setWebAutolockMinutes);
  const [extensionMinutes, setExtensionMinutes] = useAutolockValue(
    getExtensionAutolockMinutes,
    setExtensionAutolockMinutes,
  );

  return (
    <View className="rounded-2xl bg-surface1 overflow-hidden p-5">
      <View className="mb-1 flex-row items-center">
        <Lock size={16} color="#a1a1aa" />
        <Text className="ml-2 text-sm font-semibold text-primary-text">Autolock</Text>
      </View>
      <Text className="text-sm text-muted-text">
        Voult locks itself after you stop using it, so an unattended browser is never left with
        your vault open.
      </Text>

      <View className="mt-5">
        <TimerRow
          icon={Monitor}
          label="Web app"
          description="Locks this browser session after a period without activity, and unloads your vault keys."
          minutes={webMinutes}
          onChange={setWebMinutes}
        />
        <TimerRow
          icon={Puzzle}
          label="Browser extension"
          description="Locks the extension after a period without activity, before it will release a saved credential."
          minutes={extensionMinutes}
          onChange={setExtensionMinutes}
          footnote="Not applied yet — the extension still reads its own timeout. Until this is wired up, set it from the extension's settings screen."
        />
      </View>
    </View>
  );
}
