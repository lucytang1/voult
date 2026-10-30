import { sync, SyncRateLimited } from "./index";
import { setSyncStatus } from "../state";
import { useAppStore } from "../state";

export type SyncTrigger =
  | "window-focus"
  | "network-reconnect"
  | "forced"
  | "intent-created";

/** Upper bound on a server-dictated retry. The next attempt either succeeds or
 *  returns a fresh `Retry-After`; no need to honour an hour-long window. */
const MAX_RETRY_DELAY_MS = 60_000;

class SyncScheduler {
  private running = false; // a sync loop is active
  private pending = false; // a re-run was requested while running
  // A 429 delay armed by the previous run. Single-shot and coalesced with any
  // other trigger: never a poller.
  private retryTimer: ReturnType<typeof setTimeout> | null = null;

  /** Fire-and-forget entry point used by ALL triggers (blackbox). */
  requestSync(trigger?: SyncTrigger): void {
    // A new trigger makes a scheduled retry redundant. Clear it first so two
    // runs cannot be queued for the same intents.
    this.clearRetry();

    // Locked vaults have no key material; pending intents stay queued and
    // will sync on the first trigger after unlock. (sync() also self-bails.)
    const { vault, serverSession } = useAppStore.getState();
    if (vault.status !== "unlocked") {
      console.info("[SyncScheduler] skipping sync: vault is locked");
      return;
    }
    // M2: an unlocked vault with a dead cookie cannot push anything — every
    // call would 401. Skipping here avoids a pointless request storm and, more
    // importantly, avoids the 401 interceptor re-running teardown in a loop
    // while the user is on the lock screen re-authenticating.
    if (serverSession !== "active") {
      console.info("[SyncScheduler] skipping sync: server session not active");
      return;
    }
    if (this.running) {
      // Coalesce: mark a follow-up run instead of starting a second sync.
      this.pending = true;
      return;
    }
    void this.loop();
  }

  private clearRetry(): void {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  /**
   * Arms one delayed re-run after a 429. The callback goes through
   * `requestSync`, which re-checks lock/session state — so a vault that locks
   * while the timer is armed runs nothing at all (and the next trigger clears
   * the dead timer).
   */
  private scheduleRetry(retryAfterMs: number): void {
    this.clearRetry();
    const delay = Math.max(1_000, Math.min(retryAfterMs, MAX_RETRY_DELAY_MS));
    console.info("[SyncScheduler] rate limited; retrying later", { delay });
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.requestSync("forced");
    }, delay);
  }

  private async loop(): Promise<void> {
    this.running = true; // set synchronously before any await
    setSyncStatus(true);
    try {
      do {
        this.pending = false; // clear BEFORE running
        await this.syncOnce(); // the existing sync() blackbox
      } while (this.pending); // re-run if requested mid-sync
    } finally {
      this.running = false;
      setSyncStatus(false);
    }
  }

  private async syncOnce(): Promise<void> {
    try {
      await sync();
    } catch (error) {
      if (error instanceof SyncRateLimited) {
        this.scheduleRetry(error.retryAfterMs);
        return;
      }
      console.error("[SyncScheduler] sync failed", error);
    }
  }
}

export const syncScheduler = new SyncScheduler();
