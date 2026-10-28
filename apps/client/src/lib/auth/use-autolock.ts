import { useEffect } from "react";
import { useAppStore } from "../state";
import { persistLastActivity, readLastActivity } from "../state/selection-store";
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
 *  - The deadline is **persisted** (throttled) so closing the tab or browser
 *    does not reset the window. On mount we start from the stored timestamp,
 *    not from "now": with a 5-minute timer, one minute of use before closing
 *    and two minutes away restores for about two more minutes, while reopening
 *    after five minutes stays locked. Nothing has to run at the exact deadline
 *    while the app is closed.
 *  - A hidden tab records no activity. Walking away from the tab is exactly
 *    the case autolock exists for, so backgrounded time counts as idle.
 *    Browsers throttle background timers to ~1/min, so we also re-check the
 *    moment the tab becomes visible again.
 *  - The timeout is re-read from settings on every check, so changing the
 *    setting in Settings > Security applies immediately without remounting.
 *    Activity is recorded even under "Never" so switching to a finite timer
 *    compares against the real last-activity time rather than a fresh one.
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
/**
 * How often the last-activity timestamp is written to localStorage. Activity
 * itself can fire many times a second; the deadline only needs minute-scale
 * precision, and this keeps storage writes rare.
 */
const ACTIVITY_PERSIST_MS = 10_000;

export function useAutolock(): void {
  const vaultId = useAppStore((s) => s.session?.vaultId ?? null);
  const isLocked = useAppStore((s) => s.vault.status !== "unlocked");

  useEffect(() => {
    if (typeof window === "undefined") return;
    // Nothing to auto-lock without a selected vault, and nothing to protect
    // once the keys are already gone.
    if (!vaultId || isLocked) return;

    // Resume the window from durable state. `commitVaultUnlock` writes "now"
    // on a real unlock, so this only resumes a session that was restored or
    // one whose timer state survived a closed tab.
    let lastActivity = readLastActivity(vaultId) ?? Date.now();
    let lastRecordedAt = 0;
    let lastPersistedAt = 0;
    let firing = false;

    const persist = (at: number) => {
      lastPersistedAt = at;
      persistLastActivity(vaultId, at);
    };

    const recordActivity = () => {
      // A hidden tab is not "in use". Leaving it hidden still ages the vault.
      if (document.visibilityState === "hidden") return;
      const now = Date.now();
      if (now - lastRecordedAt < ACTIVITY_THROTTLE_MS) return;
      lastRecordedAt = now;
      lastActivity = now;
      if (now - lastPersistedAt >= ACTIVITY_PERSIST_MS) persist(now);
    };

    const check = async () => {
      // Re-read every tick so a settings change takes effect without a reload.
      const minutes = getWebAutolockMinutes();
      if (minutes <= 0) return;
      // Another tab may have recorded activity more recently; its timestamp is
      // shared through localStorage, so use the later of the two. Without this,
      // an idle background tab could lock the vault while the user is actively
      // working in a sibling tab.
      const shared = readLastActivity(vaultId);
      if (shared !== null && shared > lastActivity) lastActivity = shared;
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
      if (document.visibilityState === "visible") {
        void check();
      } else {
        // Persist on the way out (hidden tab, minimized window) so the
        // deadline is accurate if the process is frozen or closed.
        persist(lastActivity);
      }
    };

    // Persist synchronously before unload; localStorage is sync by design.
    const onPageHide = () => persist(lastActivity);

    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, recordActivity, { passive: true, capture: true });
    }
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("pagehide", onPageHide);
    // Evaluate immediately: a restart may already be past the deadline.
    void check();
    const timer = window.setInterval(() => void check(), CHECK_INTERVAL_MS);

    return () => {
      for (const event of ACTIVITY_EVENTS) {
        window.removeEventListener(event, recordActivity, { capture: true });
      }
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("pagehide", onPageHide);
      window.clearInterval(timer);
    };
  }, [vaultId, isLocked]);
}
