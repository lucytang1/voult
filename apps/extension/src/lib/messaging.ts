// Typed chrome.runtime message protocol between popup / content / worker.
//
// The page itself can never reach the worker: only messages from our own
// content-script context are handled (`sender.id` checked in sw.ts), and
// privileged decisions (origin, matching, fill payload) always derive from
// `sender.tab.url` in the worker — never from page-supplied strings.

import type { VaultItem, SsoProvider } from "@voult/vault-core";
export type { VaultItem, SsoProvider };

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
  /** "Continue with X" options linked to this login (may coexist with a password). */
  ssoProviders: SsoProvider[];
}

export type PopupStatus = "needs-onboarding" | "locked" | "unlocked";

export interface PopupState {
  status: PopupStatus;
  vaultId: string | null;
  serverUrl: string;
  lockTimeoutMinutes: number;
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
  | { type: "LOGIN_CANDIDATE"; username: string; password: string }
  | { type: "SAVE_DECISION"; username: string; password: string; mode: "save" | "update" }
  // OAuth sign-in memory: content reports offered providers + clicks; the
  // worker (which stamps origins from sender.tab.url) decides whether the
  // return trip looks like a completed SSO and answers whether to prompt.
  | { type: "OAUTH_CLICK"; provider: SsoProvider; offered: SsoProvider[] }
  | { type: "OAUTH_PAGE_STATE"; offers: SsoProvider[]; hasLoginForm: boolean; path: string }
  | { type: "SAVE_OAUTH_DECISION"; provider: SsoProvider }
  | { type: "NEVER_ORIGIN" };

export type SavePrompt =
  | { prompt: false }
  | { prompt: true; mode: "save" | "update"; origin: string; username: string };

export type OAuthSavePrompt =
  | { prompt: false }
  | { prompt: true; provider: SsoProvider; origin: string };

/** Fill payload returned for exactly one credential, on explicit gesture. */
export interface FillPayload {
  username: string;
  password: string;
}

/**
 * Fill refusal. `ssoProviders` is set when the id names a passwordless SSO
 * login: there is no secret to release, and the content script should
 * highlight the site's own SSO button(s) instead. Plain `{ error }` without
 * it means a hard failure. `ssoProvider` (singular) is kept for back-compat
 * with older content scripts — prefer `ssoProviders`.
 */
export interface FillError {
  error: string;
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
