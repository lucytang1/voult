import { sync } from "./index";
import { setSyncStatus } from "../state";

export type SyncTrigger =
  | "window-focus"
  | "network-reconnect"
  | "forced"
  | "intent-created";

class SyncScheduler {
  private running = false; // a sync loop is active
  private pending = false; // a re-run was requested while running

  /** Fire-and-forget entry point used by ALL triggers (blackbox). */
  requestSync(trigger?: SyncTrigger): void {
    if (this.running) {
      // Coalesce: mark a follow-up run instead of starting a second sync.
      this.pending = true;
      return;
    }
    void this.loop();
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
      console.error("[SyncScheduler] sync failed", error);
    }
  }
}

export const syncScheduler = new SyncScheduler();
