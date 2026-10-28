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
  adoptSessionProbe,
  clearPendingPrompt,
  confirmPendingPrompt,
  credentialForFill,
  clearPendingOAuthFor,
  evaluateCandidate,
  evaluateOAuthPageState,
  getPendingPrompt,
  getPopupState,
  handleAlarm,
  isUnlocked,
  logout,
  markNeverOrigin,
  normalizeServerUrl,
  oauthSignInsForFill,
  pairWithCode,
  publishLock,
  pushSave,
  pushSaveOAuth,
  queryLogins,
  recordOAuthClick,
  resetOnboarding,
  restoreOnStartup,
  saveOnboarding,
  setFolderSelection,
  setPendingPrompt,
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
  setSessionValue,
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

// Silent device unlock on worker/browser startup, governed by the durable lock
// policy (`restoreOnStartup`): Never or a still-open idle window restores;
// a manual/peer lock or an elapsed idle deadline stays locked.
// When nothing is onboarded yet, opportunistically adopt the web session's
// vault so the popup opens on the password screen instead of Connect.
async function startupUnlock(): Promise<void> {
  try {
    let id = await getLocalValue<string>(ACTIVE_VAULT_KEY);
    if (!id) {
      id = await adoptSessionProbe();
      if (!id) return;
    }
    // Fast path for a lock recorded earlier in this browser session. The
    // durable lock record is what survives a browser restart.
    if (await getSessionValue<number>(LOCKED_FLAG_KEY)) return;
    const unlocked = await restoreOnStartup();
    if (!unlocked) await setSessionValue(LOCKED_FLAG_KEY, 1);
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
          case "ADOPT_SESSION": {
            // Auto-discovery: no vault typed — adopt the web session's vault
            // when one exists in this browser profile.
            const id = await adoptSessionProbe();
            if (!id) throw new Error("No web session found — sign in to the web app first, or pair with a code.");
            sendResponse(await getPopupState());
            break;
          }
          case "PAIR_WITH_CODE":
            await pairWithCode(msg.code, msg.serverUrl);
            sendResponse(await getPopupState());
            break;
          case "RESET_ONBOARDING":
            await resetOnboarding();
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
              // 0 means "Never" (same sentinel as the web app). Clamp to the
              // shared 4-hour ceiling; a corrupt value must not disable the
              // timer silently.
              const raw = Math.floor(msg.lockTimeoutMinutes);
              const mins = Number.isFinite(raw) ? Math.min(240, Math.max(0, raw)) : 5;
              await setLocalValue("voult.lockTimeoutMinutes", mins);
            }
            sendResponse(await getPopupState());
            break;
          }
          case "SET_FOLDER": {
            // The popup's folder filter outlives the popup: the worker keeps it
            // (cleared by every lock) and uses it to scope page suggestions and
            // save destinations. The reply is a full state so this site's
            // matches reflect the new scope.
            await setFolderSelection(msg.folderId);
            sendResponse(await getPopupState(msg.tabOrigin));
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
            // Passwordless SSO logins hold no secret: answer with a highlight
            // directive (methods) instead of a credential. No password ever
            // crosses. `ssoProviders` / `ssoProvider` are also sent so a
            // content script from a different build still degrades to a
            // highlight rather than a hard failure.
            const sso = oauthSignInsForFill(msg.id);
            if (sso && sso.length > 0) {
              const providers = sso.map((s) => s.provider);
              sendResponse({
                error: "This login uses Continue-with-SSO — no password to fill.",
                sso,
                ssoProviders: providers,
                ssoProvider: providers[0],
              });
              break;
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
            // A typed password wins over any in-flight SSO click on this
            // origin — the user chose the password path.
            clearPendingOAuthFor(candidateOrigin);
            // The tab's own icon is what the user sees on the tab; the page's
            // declared icon is only the fallback hint.
            const icon = sender.tab?.favIconUrl ?? msg.faviconUrl ?? null;
            const verdict = await evaluateCandidate(msg.username, msg.password, candidateOrigin, icon);
            // Retain the prompted capture (memory only) so a sign-in redirect
            // destroying the page card can re-show it on the next page.
            if (verdict.prompt) {
              setPendingPrompt({
                username: msg.username,
                password: msg.password,
                origin: verdict.origin,
                mode: verdict.mode,
                faviconUrl: verdict.faviconUrl ?? icon,
                at: Date.now(),
              });
            } else if (!verdict.prompt) {
              // Already saved / never-listed: drop any stale prompt so the
              // next page does not nag for a resolved capture.
              clearPendingPrompt();
            }
            sendResponse(verdict);
            break;
          }
          case "CHECK_PENDING_SAVE": {
            // Fresh page load asking whether a pre-redirect capture is still
            // awaiting a decision. Origin stamped from the sender tab.
            const pageOrigin = tabOrigin(sender.tab);
            if (!pageOrigin) {
              sendResponse({ prompt: false });
              break;
            }
            sendResponse(await getPendingPrompt(pageOrigin));
            break;
          }
          case "CONFIRM_PENDING_SAVE": {
            // User confirmed the re-shown card on the post-redirect page.
            // The secret comes from worker memory — the new page never held it.
            const decisionOrigin = tabOrigin(sender.tab);
            if (!decisionOrigin) throw new Error("Unknown tab origin.");
            const canonical = originOfUrl(decisionOrigin);
            const icon = sender.tab?.favIconUrl ?? msg.faviconUrl ?? null;
            const result = await confirmPendingPrompt(canonical, icon, msg.folderId);
            sendResponse({ saved: result.saved, offline: result.offline });
            break;
          }
          case "DISMISS_PENDING_SAVE": {
            clearPendingPrompt();
            sendResponse({ ok: true });
            break;
          }
          case "SAVE_DECISION": {
            // User confirmed in the page banner. Plaintext crossed contexts
            // only for this explicit gesture; the worker pushes then drops it.
            const decisionOrigin = tabOrigin(sender.tab);
            if (!decisionOrigin) throw new Error("Unknown tab origin.");
            const canonical = originOfUrl(decisionOrigin);
            // Icon priority: the browser's own tab icon first (it IS what the
            // tab shows — DOM scraping can pick a different theme/size
            // variant), then the page-declared icon. The worker re-validates
            // either; origin is still stamped from the sender tab.
            const icon = sender.tab?.favIconUrl ?? msg.faviconUrl ?? null;
            const result = await pushSave(
              msg.username,
              msg.password,
              canonical,
              msg.mode,
              icon,
              msg.folderId,
            );
            // Resolved here — the post-redirect page must not re-prompt.
            // Offline keeps the retained prompt so a later page can retry.
            if (result.saved) clearPendingPrompt();
            sendResponse({ saved: result.saved, offline: result.offline });
            break;
          }
          case "NEVER_ORIGIN": {
            const neverOrigin = tabOrigin(sender.tab);
            if (neverOrigin) await markNeverOrigin(neverOrigin);
            clearPendingPrompt();
            sendResponse({ ok: true });
            break;
          }
          case "OAUTH_CLICK": {
            // Click on a "Continue with X" button. Origin stamped from the
            // sender tab — page claims ignored. Fire-and-forget for the page.
            const clickOrigin = tabOrigin(sender.tab);
            if (clickOrigin) recordOAuthClick(msg.provider, clickOrigin, sender.tab?.id);
            sendResponse({ ok: true });
            break;
          }
          case "OAUTH_PAGE_STATE": {
            // SSO page (re)loaded or SPA-navigated. The worker matches the
            // page against the in-flight click and answers prompt or not.
            const pageOrigin = tabOrigin(sender.tab);
            if (!pageOrigin) {
              sendResponse({ prompt: false });
              break;
            }
            sendResponse(
              await evaluateOAuthPageState(
                msg.offers,
                msg.hasLoginForm,
                msg.path,
                pageOrigin,
                sender.tab?.favIconUrl ?? msg.faviconUrl ?? null,
              ),
            );
            break;
          }
          case "SAVE_OAUTH_DECISION": {
            // User confirmed "Signed in with X?" in the page banner. No
            // secret crosses contexts — just the provider and the account the
            // user typed.
            const decisionOrigin = tabOrigin(sender.tab);
            if (!decisionOrigin) throw new Error("Unknown tab origin.");
            const canonical = originOfUrl(decisionOrigin);
            const icon = sender.tab?.favIconUrl ?? msg.faviconUrl ?? null;
            const result = await pushSaveOAuth(
              msg.provider,
              msg.account,
              canonical,
              icon,
              msg.folderId,
            );
            sendResponse({ saved: result.saved, offline: result.offline });
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

// Screen lock always locks the vault immediately. It is an environmental event
// like the idle timer, not a deliberate user "Lock" action, so it stays local
// to this surface and does not bump the shared epoch.
chrome.idle.onStateChanged.addListener((state) => {
  if (state === "locked" && isUnlocked()) {
    console.info("[voult] locked (screen locked)");
    void publishLock("autolock");
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
