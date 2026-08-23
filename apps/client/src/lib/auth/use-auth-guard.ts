import { useEffect } from "react";
import { useRouter } from "expo-router";
import { useAppStore } from "../state";
import type { AuthState } from "../state/type";

/**
 * Central routing guard for the three-state auth machine
 * (not_authenticated / locked / unlocked). Each page declares the states it
 * may render in; on mismatch the user is redirected to the canonical page:
 *
 *   not_authenticated -> /auth/login
 *   locked            -> /lock
 *   unlocked          -> /home
 */
export function useAuthGuard(allowed: AuthState[]) {
  const router = useRouter();
  const session = useAppStore((s) => s.session);
  const isLocked = useAppStore((s) => s.isLocked);

  const state: AuthState = !session
    ? "not_authenticated"
    : isLocked
      ? "locked"
      : "unlocked";

  useEffect(() => {
    if (allowed.includes(state)) return;
    const target =
      state === "unlocked"
        ? "/home"
        : state === "locked"
          ? "/lock"
          : "/auth/login";
    router.replace(target as any);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  return state;
}
