// Popup-side helpers: message RPC, clipboard, active tab, and safe tab opens.
// These touch only DOM/browser APIs — no vault state, no secrets beyond the
// transient strings the caller explicitly copies.

import { sendMessage } from "../lib/messaging";
import type { ExtensionMessage } from "../lib/messaging";

type RpcResponse<T> = T | { error: string };

export function isErr(r: unknown): r is { error: string } {
  return !!r && typeof r === "object" && "error" in (r as Record<string, unknown>);
}

/** One request/response round-trip with the service worker. */
export async function call<T>(msg: ExtensionMessage): Promise<T> {
  const res = await sendMessage<RpcResponse<T>>(msg);
  if (isErr(res)) throw new Error(res.error);
  return res;
}

/** Active tab URL (used to ask the worker for this site's matches). */
export async function activeTabUrl(): Promise<string | undefined> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url;
  } catch {
    return undefined;
  }
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Open an http(s) URL in a new tab. The vault stores canonical origins, but
 * re-validate here anyway: a malformed or non-web value must never become a
 * `chrome.tabs.create` target (file:, javascript:, chrome:// …).
 */
export function openExternal(url: string | undefined): void {
  if (!url) return;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return;
    void chrome.tabs.create({ url: parsed.toString() });
  } catch {
    // Not a URL — nothing to open.
  }
}

/** Host part of a canonical origin, for compact row subtitles. */
export function hostOf(origin: string | undefined): string {
  if (!origin) return "";
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

/** Short vault label for confirmations ("Vault 1234abcd…"). */
export function shortVaultId(vaultId: string | null): string {
  return vaultId ? `${vaultId.slice(0, 8)}…` : "this vault";
}
