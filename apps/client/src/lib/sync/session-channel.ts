/**
 * Same-origin session broadcast (web tab ↔ web tab).
 *
 * The extension lives on `chrome-extension://` and shares neither storage nor
 * BroadcastChannel with the web origin, so cross-surface signalling always
 * goes through the server `lock_epoch` counter (see `use-session-sync`). This
 * channel is only the instant path between open web tabs — no secrets cross
 * it, just `{ type, vaultId, lockEpoch }`.
 */

export type SessionBroadcastType = "locked" | "logged-out" | "vault-switch";

export interface SessionBroadcast {
  type: SessionBroadcastType;
  vaultId: string | null;
  lockEpoch: number | null;
  source: string;
  at: number;
}

const CHANNEL_NAME = "voult:session";
const STORAGE_PING_KEY = "voult:session-ping";

function tabSource(): string {
  try {
    let id = sessionStorage.getItem("voult:tab-id");
    if (!id) {
      id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
      sessionStorage.setItem("voult:tab-id", id);
    }
    return id;
  } catch {
    return "unknown-tab";
  }
}

function hasBroadcastChannel(): boolean {
  return typeof window !== "undefined" && "BroadcastChannel" in window;
}

/** Emit a session event to other web tabs (no-op outside the browser). */
export function postSessionEvent(
  type: SessionBroadcastType,
  vaultId: string | null,
  lockEpoch: number | null,
): void {
  if (typeof window === "undefined") return;
  const event: SessionBroadcast = {
    type,
    vaultId,
    lockEpoch,
    source: tabSource(),
    at: Date.now(),
  };
  if (hasBroadcastChannel()) {
    try {
      const channel = new BroadcastChannel(CHANNEL_NAME);
      channel.postMessage(event);
      channel.close();
      return;
    } catch {
      // Fall through to the storage ping.
    }
  }
  // Fallback for environments without BroadcastChannel: the storage event
  // fires in every OTHER tab when localStorage changes.
  try {
    localStorage.setItem(STORAGE_PING_KEY, JSON.stringify(event));
  } catch {
    // Non-fatal: peers converge via the next check-on-use GET /session.
  }
}

/** Subscribe to other tabs' session events. Returns an unsubscribe function. */
export function subscribeSessionEvents(
  onEvent: (event: SessionBroadcast) => void,
): () => void {
  if (typeof window === "undefined") return () => {};
  const own = tabSource();

  if (hasBroadcastChannel()) {
    const channel = new BroadcastChannel(CHANNEL_NAME);
    channel.onmessage = (message: MessageEvent<SessionBroadcast>) => {
      const event = message.data;
      if (!event || event.source === own) return;
      onEvent(event);
    };
    return () => channel.close();
  }

  const onStorage = (e: StorageEvent) => {
    if (e.key !== STORAGE_PING_KEY || !e.newValue) return;
    try {
      const event = JSON.parse(e.newValue) as SessionBroadcast;
      if (!event || event.source === own) return;
      onEvent(event);
    } catch {
      // Ignore malformed pings; check-on-use converges anyway.
    }
  };
  window.addEventListener("storage", onStorage);
  return () => window.removeEventListener("storage", onStorage);
}
