import { useEffect } from "react";
import { useRouter } from "expo-router";
import { useAppStore } from "../state";
import type { VaultState } from "../state/vault-state";
import { routeFor } from "../state/vault-state";

/**
 * The three routing states, named as the union's `status` discriminant.
 */
export type VaultRouteState = VaultState["status"];

/**
 * Central routing guard for the three-state vault machine
 * (no_vault / locked / unlocked). Each page declares the states it may render
 * in; on mismatch the user is redirected to the canonical page:
 *
 *   no_vault -> /    (landing: choose create locally or cloud sync)
 *   locked   -> /lock
 *   unlocked -> /home
 *
 * Routing reads `vault.status` straight off the union rather than deriving a
 * label from `session` + `isLocked`. That is the point of the migration: the
 * screen the user lands on is decided by the same value that holds the key, so
 * "unlocked but routed to /lock" is not expressible.
 */
export function useAuthGuard(allowed: VaultRouteState[]) {
  const router = useRouter();
  const vault = useAppStore((s) => s.vault);
  const state = vault.status;

  useEffect(() => {
    if (allowed.includes(state)) return;
    router.replace(routeFor(vault) as any);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  return state;
}
