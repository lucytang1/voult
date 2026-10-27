// Typed chrome.runtime message protocol between popup / content / worker.
//
// The page itself can never reach the worker: only messages from our own
// content-script context are handled (`sender.id` checked in sw.ts), and
// privileged decisions (origin, matching, fill payload) always derive from
// `sender.tab.url` in the worker — never from page-supplied strings.

import type { VaultItem, Folder, SsoProvider, SsoSignIn } from "@voult/vault-core";
export type { VaultItem, Folder, SsoProvider, SsoSignIn };

export type Rank = "exact" | "linked" | "subdomain";

export interface LoginMatch {
  id: string;
  username: string;
  /** Display label: site text when present, else origin. */
  label: string;
  origin: string;
  rank: Rank;
  /** True when the item stores a password (fillable). */
  hasPassword: boolean;
  /**
   * "Continue with X" methods on this login, each naming the account it
   * authenticates (may coexist with a password). Never bare providers: an
   * account is what makes the row answer "which account is this?".
   */
  sso: SsoSignIn[];
  /** Display-only icon URL (stored favicon or `<origin>/favicon.ico`). */
  faviconUrl?: string;
}

export type PopupStatus = "needs-onboarding" | "locked" | "unlocked";

export interface PopupState {
  status: PopupStatus;
  vaultId: string | null;
  /** Decrypted label only — display, never identity. Null while locked. */
  vaultName: string | null;
  serverUrl: string;
  lockTimeoutMinutes: number;
  /** Folder list from the decrypted document (empty while locked). */
  folders: Folder[];
  /** Present when unlocked: ranked matches first for tabOrigin when given. */
  items: VaultItem[] | null;
  matches: LoginMatch[] | null;
  version: number | null;
  insecureOrigin: boolean;
}

export type ExtensionMessage =
  | { type: "GET_STATE"; tabOrigin?: string }
  | { type: "PING" }
  | { type: "SAVE_ONBOARDING"; vaultId: string; serverUrl: string }
  // Password-only onboarding: adopt the web session's vault (no typing) or
  // redeem a one-time pairing code shown in the web app. RESET_ONBOARDING
  // forgets the pinned vault and returns to the Connect screen.
  | { type: "ADOPT_SESSION" }
  | { type: "PAIR_WITH_CODE"; code: string; serverUrl?: string }
  | { type: "RESET_ONBOARDING" }
  | { type: "UNLOCK_WITH_PASSWORD"; password: string }
  | { type: "UNLOCK_WITH_DEVICE" }
  | { type: "LOCK" }
  | { type: "LOGOUT" }
  | { type: "SET_SETTINGS"; serverUrl?: string; lockTimeoutMinutes?: number }
  // Content → worker. No URL/page claims: the worker stamps origins from
  // sender.tab.url exclusively.
  | { type: "QUERY_LOGINS" }
  | { type: "FILL_CREDENTIAL"; id: string }
  // Popup → worker → content (active tab).
  | { type: "FILL_ACTIVE_TAB"; id: string }
  // M2 save flow: content reports a capture; worker dedupes and answers
  // whether to prompt, then content relays the user's banner decision.
  // faviconUrl is the page's declared icon (fallback hint — the worker
  // prefers the tab's own icon and re-validates either; origin is still
  // stamped from sender.tab.url).
  | { type: "LOGIN_CANDIDATE"; username: string; password: string; faviconUrl?: string | null }
  | { type: "SAVE_DECISION"; username: string; password: string; mode: "save" | "update"; faviconUrl?: string | null }
  // Redirect survival: the login banner lives in the page DOM, so a sign-in
  // redirect destroys it. The worker therefore retains the last prompted
  // capture (memory only) and each freshly loaded page re-asks for it.
  | { type: "CHECK_PENDING_SAVE" }
  // Confirm uses the worker-retained credentials — the post-redirect page has
  // no password field to read, and this avoids sending the secret back down.
  | { type: "CONFIRM_PENDING_SAVE"; faviconUrl?: string | null }
  | { type: "DISMISS_PENDING_SAVE" }
  // OAuth sign-in memory: content reports offered providers + clicks; the
  // worker (which stamps origins from sender.tab.url) decides whether the
  // return trip looks like a completed SSO and answers whether to prompt.
  | { type: "OAUTH_CLICK"; provider: SsoProvider; offered: SsoProvider[] }
  | { type: "OAUTH_PAGE_STATE"; offers: SsoProvider[]; hasLoginForm: boolean; path: string; faviconUrl?: string | null }
  // `account` is the IdP account this sign-in used, or "" when the vault knows
  // no account for that provider (the worker then stores the provider alone).
  | { type: "SAVE_OAUTH_DECISION"; provider: SsoProvider; account: string; faviconUrl?: string | null }
  | { type: "NEVER_ORIGIN" };

export type SavePrompt =
  | { prompt: false }
  | { prompt: true; mode: "save" | "update"; origin: string; username: string };

/**
 * Whether a completed SSO sign-in on `origin` deserves a save prompt.
 * `accounts` are the vault's known accounts for that provider — the banner
 * offers them as a choice because a password manager cannot observe which IdP
 * account was used. Empty means "save as Sign in with <provider>".
 */
export type OAuthSavePrompt =
  | { prompt: false }
  | { prompt: true; provider: SsoProvider; origin: string; accounts: string[] };

/** Fill payload returned for exactly one credential, on explicit gesture. */
export interface FillPayload {
  username: string;
  password: string;
}

/**
 * Fill refusal. `sso` is set when the id names a passwordless SSO login: there
 * is no secret to release, and the content script should highlight the site's
 * own SSO button(s) instead. Plain `{ error }` without it means a hard
 * failure. `ssoProviders` (provider list, no accounts) and `ssoProvider` are
 * kept alongside it so a content script running a different build than the
 * worker still degrades to a highlight instead of crashing.
 */
export interface FillError {
  error: string;
  sso?: SsoSignIn[];
  ssoProviders?: SsoProvider[];
  ssoProvider?: SsoProvider;
}

/** Human label for an SSO provider ("Google", "GitHub", …). For module
 * contexts (popup) only — content scripts use the copy in content/oauth.ts
 * so their bundle stays a single import-free IIFE (see oauth.ts). */
export function ssoProviderLabel(p?: SsoProvider): string {
  switch (p) {
    case "google": return "Google";
    case "github": return "GitHub";
    case "apple": return "Apple";
    case "microsoft": return "Microsoft";
    case "custom": return "SSO";
    default: return "SSO";
  }
}

export function sendMessage<T>(msg: ExtensionMessage): Promise<T> {
  return chrome.runtime.sendMessage(msg) as Promise<T>;
}
