// Voult extension service worker (MV3, vanilla TS — no DOM, no React).
//
// Owns all privileged state: vault key + decrypted items in memory while
// unlocked, session/device records in storage. The popup unloads when closed,
// so every popup view is a projection of this worker via messages. Content
// scripts never see the vault — only per-gesture fill payloads and match
// lists for the tab the worker derives from `sender.tab.url`.

import type { ExtensionMessage } from "../lib/messaging";
import { EXTENSION_VERSION } from "./version";
import {
  credentialForFill,
  evaluateCandidate,
  getPopupState,
  handleAlarm,
  isUnlocked,
  logout,
  markNeverOrigin,
  normalizeServerUrl,
  publishLock,
  pushSave,
  queryLogins,
  saveOnboarding,
  syncSession,
  unlockWithDevice,
  unlockWithPassword,
} from "./vault";
import { originOfUrl } from "@voult/vault-core";
import {
  ACTIVE_VAULT_KEY,
  LOCKED_FLAG_KEY,
  getLocalValue,
  getSessionValue,
  setLocalValue,
} from "../lib/storage";

function tabOrigin(tab: chrome.tabs.Tab | undefined): string | null {
  if (!tab?.url) return null;
  try {
    return originOfUrl(tab.url);
  } catch {
    return null;
  }
}

chrome.runtime.onInstalled.addListener((details) => {
  // Install/update only — never secrets, origins, or vault material.
  console.info(`[voult] extension ${details.reason}`, { version: EXTENSION_VERSION });
});

// Silent device unlock on worker startup (fresh browser session), unless the
// user explicitly locked (locked flag survives in chrome.storage.session).
async function startupUnlock(): Promise<void> {
  try {
    if (await getSessionValue<number>(LOCKED_FLAG_KEY)) return;
    const id = await getLocalValue<string>(ACTIVE_VAULT_KEY);
    if (!id) return;
    await unlockWithDevice();
  } catch (e) {
    console.warn("[voult] startup unlock skipped", e);
  }
}

void startupUnlock();

chrome.runtime.onMessage.addListener(
  (msg: ExtensionMessage, sender, sendResponse: (r: unknown) => void) => {
    // Only our own contexts may message the worker.
    if (sender.id !== chrome.runtime.id) return false;
    void (async () => {
      try {
        switch (msg.type) {
          case "PING":
            sendResponse("PONG");
            break;
          case "GET_STATE": {
            // Check-on-use convergence: a peer's lock/logout/switch lands
            // before the popup renders. Offline → render from local state.
            try {
              await syncSession();
            } catch {
              // Offline — popup reflects last known state.
            }
            // tabOrigin comes from the popup (activeTab-granted tab URL).
            sendResponse(await getPopupState(msg.tabOrigin));
            break;
          }
          case "SAVE_ONBOARDING":
            await saveOnboarding(msg.vaultId, msg.serverUrl);
            sendResponse(await getPopupState());
            break;
          case "UNLOCK_WITH_PASSWORD":
            // The password lives only in this transient message scope; the
            // worker derives + discards it (never stored, never logged).
            await unlockWithPassword(msg.password);
            sendResponse(await getPopupState());
            break;
          case "UNLOCK_WITH_DEVICE": {
            const ok = await unlockWithDevice();
            if (!ok) throw new Error("Device unlock unavailable — enter the master password.");
            sendResponse(await getPopupState());
            break;
          }
          case "LOCK":
            await publishLock();
            sendResponse(await getPopupState());
            break;
          case "LOGOUT":
            await logout();
            sendResponse(await getPopupState());
            break;
          case "SET_SETTINGS": {
            if (msg.serverUrl !== undefined) {
              const normalized = normalizeServerUrl(msg.serverUrl);
              await setLocalValue("voult.serverUrl", normalized);
            }
            if (msg.lockTimeoutMinutes !== undefined) {
              const mins = Math.min(120, Math.max(1, Math.floor(msg.lockTimeoutMinutes)));
              await setLocalValue("voult.lockTimeoutMinutes", mins);
            }
            sendResponse(await getPopupState());
            break;
          }
          case "QUERY_LOGINS": {
            // Origin is stamped from the sender tab — page claims ignored.
            const origin = tabOrigin(sender.tab);
            sendResponse(origin ? queryLogins(origin) : []);
            break;
          }
          case "FILL_CREDENTIAL": {
            const origin = tabOrigin(sender.tab);
            if (!origin) throw new Error("Unknown tab origin.");
            // Pre-release convergence: never hand out a credential after a
            // peer locked/logged-out/switched, even if the local worker has
            // not yet converged (stale-unlocked). Offline → local state rules.
            try {
              await syncSession();
            } catch {
              // Offline — fall through to the in-memory match check.
            }
            // Confirm the credential actually matches this tab before
            // releasing it — a compromised renderer asking for an unrelated
            // id gets nothing.
            const matches = queryLogins(origin);
            if (!matches.some((m) => m.id === msg.id)) {
              throw new Error("Login does not match this site.");
            }
            sendResponse(credentialForFill(msg.id));
            break;
          }
          case "FILL_ACTIVE_TAB": {
            // Same pre-release convergence as FILL_CREDENTIAL.
            try {
              await syncSession();
            } catch {
              // Offline — fall through to local state.
            }
            if (!isUnlocked()) throw new Error("Vault is locked.");
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab?.id) throw new Error("No active tab.");
            await chrome.tabs.sendMessage(tab.id, { type: "VOULT_FILL_ONE", id: msg.id });
            sendResponse({ ok: true });
            break;
          }
          case "LOGIN_CANDIDATE": {
            // Dedupe in the worker against the unlocked cache. Locked (or
            // never-listed, or identical) captures resolve to no prompt.
            const candidateOrigin = tabOrigin(sender.tab);
            if (!candidateOrigin) {
              sendResponse({ prompt: false });
              break;
            }
            sendResponse(
              await evaluateCandidate(msg.username, msg.password, candidateOrigin),
            );
            break;
          }
          case "SAVE_DECISION": {
            // User confirmed in the page banner. Plaintext crossed contexts
            // only for this explicit gesture; the worker pushes then drops it.
            const decisionOrigin = tabOrigin(sender.tab);
            if (!decisionOrigin) throw new Error("Unknown tab origin.");
            const canonical = originOfUrl(decisionOrigin);
            const result = await pushSave(msg.username, msg.password, canonical, msg.mode);
            sendResponse({ saved: result.saved, offline: result.offline });
            break;
          }
          case "NEVER_ORIGIN": {
            const neverOrigin = tabOrigin(sender.tab);
            if (neverOrigin) await markNeverOrigin(neverOrigin);
            sendResponse({ ok: true });
            break;
          }
          default:
            console.warn("[voult] unhandled message type");
            sendResponse({ error: "unhandled" });
        }
      } catch (e) {
        // Errors cross the message boundary as values (never throw across).
        // Messages carry no secrets — only short failure reasons.
        sendResponse({ error: e instanceof Error ? e.message : "Request failed." });
      }
    })();
    return true;
  },
);

chrome.alarms.onAlarm.addListener((alarm) => {
  void handleAlarm(alarm);
});

// Screen lock always locks the vault immediately (publishing best-effort so
// the web app converges); system idle is covered by the inactivity alarm.
chrome.idle.onStateChanged.addListener((state) => {
  if (state === "locked" && isUnlocked()) {
    console.info("[voult] locked (screen locked)");
    void publishLock();
  }
});

// Keyboard shortcut (Ctrl/Cmd+Shift+L): fill the single best match in the
// active tab, or nudge the tab to show its suggestions when ambiguous.
chrome.commands.onCommand.addListener((command) => {
  if (command !== "fill-best-match") return;
  void (async () => {
    if (!isUnlocked()) return;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url) return;
    let pageOrigin: string;
    try {
      pageOrigin = originOfUrl(tab.url);
    } catch {
      return;
    }
    const matches = queryLogins(pageOrigin);
    if (matches.length === 0) return;
    await chrome.tabs.sendMessage(tab.id, {
      type: "VOULT_FILL_BEST",
      ids: matches.map((m) => m.id),
    });
  })();
});

console.info(`[voult] service worker ready (v${EXTENSION_VERSION})`);
