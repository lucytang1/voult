import { useEffect, useRef } from "react";
import { useAppStore } from "../state";
import { queryClient } from "../queries/client";
import { getWebAutolockMinutes } from "../settings";
import { lockVaultNow } from "./lock";

/**
 * Web-app autolock: locks the vault after a period of inactivity.
 *
 * Design notes:
 *
 *  - Mounted once in the root layout (like useSessionSync) rather than on
 *    /home, so it keeps watching while the user is in Settings or adding an
 *    item. It only arms while a vault is unlocked.
 *  - Activity is a plain ref, not React state: pointermove fires constantly
 *    and must never trigger a re-render. A 1s write throttle keeps the ref
 *    cheap; accuracy well below a second is irrelevant for a multi-minute
 *    timeout.
 *  - A hidden tab records no activity. Walking away from the tab is exactly
 *    the case autolock exists for, so backgrounded time counts as idle.
 *    Browsers throttle background timers to ~1/min, so we also re-check the
 *    moment the tab becomes visible again.
 *  - The timeout is re-read from settings on every check, so changing the
 *    setting in Settings > Security applies immediately without remounting.
 */
const ACTIVITY_EVENTS = [
  "pointerdown",
  "pointermove",
  "keydown",
  "wheel",
  "touchstart",
  "focus",
] as const;

const ACTIVITY_THROTTLE_MS = 1000;
/** How often idle time is evaluated. Cheap; the timeout itself is minutes. */
const CHECK_INTERVAL_MS = 5000;

export function useAutolock(): void {
  const vaultId = useAppStore((s) => s.session?.vaultId ?? null);
  const isLocked = useAppStore((s) => s.isLocked);

  useEffect(() => {
    if (typeof window === "undefined") return;
    // Nothing to auto-lock without a live session, and nothing to protect once
    // the keys are already gone.
    if (!vaultId || isLocked) return;
    // "Never" — don't even attach listeners.
    if (getWebAutolockMinutes() <= 0) return;

    let lastActivity = Date.now();
    let lastRecordedAt = 0;
    let firing = false;

    const recordActivity = () => {
      // A hidden tab is not "in use". Leaving it hidden still ages the vault.
      if (document.visibilityState === "hidden") return;
      const now = Date.now();
      if (now - lastRecordedAt < ACTIVITY_THROTTLE_MS) return;
      lastRecordedAt = now;
      lastActivity = now;
    };

    const check = async () => {
      // Re-read every tick so a settings change takes effect without a reload.
      const minutes = getWebAutolockMinutes();
      if (minutes <= 0) return;
      if (Date.now() - lastActivity < minutes * 60_000) return;
      // lockVaultNow awaits the server round-trip; don't re-enter meanwhile.
      if (firing) return;
      firing = true;
      try {
        await lockVaultNow({ queryClient, reason: "idle" });
      } catch (e) {
        // Locking must not be blocked by a transient failure. isLocked is now
        // true, which disarms this effect and re-runs it only after unlock.
        console.error("Autolock failed", e);
      } finally {
        firing = false;
      }
    };

    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") void check();
    };

    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, recordActivity, { passive: true, capture: true });
    }
    document.addEventListener("visibilitychange", onVisibilityChange);
    const timer = window.setInterval(() => void check(), CHECK_INTERVAL_MS);

    return () => {
      for (const event of ACTIVITY_EVENTS) {
        window.removeEventListener(event, recordActivity, { capture: true });
      }
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.clearInterval(timer);
    };
  }, [vaultId, isLocked]);
}
