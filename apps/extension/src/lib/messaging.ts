// Typed chrome.runtime message protocol between popup / content / worker.
//
// The page itself can never reach the worker: only messages from our own
// content-script context are handled (`sender.id` checked in sw.ts), and
// privileged decisions (origin, matching, fill payload) always derive from
// `sender.tab.url` in the worker — never from page-supplied strings.

import type { VaultItem, Folder, SsoProvider, SsoSignIn } from "@voult/vault-core";
export type { VaultItem, Folder, SsoProvider, SsoSignIn };

/**
 * Match strength. There is no weaker rank: a login is offered only for its
 * exact canonical origin or an explicitly linked URL. `decideFillBest` in
 * vault-core treats any other string as weak, so a future rank cannot become
 * an automatic fill by accident.
 */
export type Rank = "exact" | "linked";

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

/**
 * Worker → content: result of the fill-best shortcut. `fillId` is the only way
 * to auto-fill, and the worker sets it only when `decideFillBest` resolved
 * exactly one exact/linked match. Otherwise the tab opens its chooser for
 * `ids` — a single weak match must never fill itself.
 */
export interface FillBestMessage {
  type: "VOULT_FILL_BEST";
  fillId?: string;
  ids: string[];
}

export type PopupStatus = "needs-onboarding" | "locked" | "unlocked";

export interface PopupState {
  status: PopupStatus;
  vaultId: string | null;
  /** Decrypted label only — display, never identity. Null while locked. */
  vaultName: string | null;
  serverUrl: string;
  lockTimeoutMinutes: number;
  /**
   * True when the server rejected the session cookie. Purely informational:
   * an unlocked vault keeps working locally; syncing/saving resumes once the
   * browser session is re-established (e.g. by signing in on the web app).
   */
  serverSessionMissing: boolean;
  /** Folder list from the decrypted document (empty while locked). */
  folders: Folder[];
  /**
   * The popup's folder filter, persisted by the worker for the unlocked
   * lifetime (cleared by every lock). `null` = All folders; `"unfiled"` = the
   * shared Unfiled bucket; anything else is a folder id. Null while locked.
   *
   * This is not just a view: it also scopes which logins are suggested on a
   * page and where a save lands, so it must come from the worker rather than
   * from per-popup React state.
   */
  selectedFolderId: string | null;
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
  // Folder filter: `folderId` is a folder id, "unfiled", or null for All
  // folders. Persisted in the worker (cleared on lock) so it survives a popup
  // close and scopes both page suggestions and save destinations. `tabOrigin`
  // lets the reply carry this site's matches under the new scope.
  | { type: "SET_FOLDER"; folderId: string | null; tabOrigin?: string }
  // Content → worker. No URL/page claims: the worker stamps origins from
  // sender.tab.url exclusively.
  | { type: "QUERY_LOGINS" }
  | { type: "FILL_CREDENTIAL"; id: string }
  // Popup → worker → content (active tab).
  | { type: "FILL_ACTIVE_TAB"; id: string }
  // M2 save flow: content reports a capture; worker dedupes and answers
  // whether to prompt, then content relays the user's save-card decision.
  // faviconUrl is the page's declared icon (fallback hint — the worker
  // prefers the tab's own icon and re-validates either; origin is still
  // stamped from sender.tab.url).
  // `folderId` is the destination the user picked in the card: a folder id,
  // or null for the Unfiled bucket. Omitted = no explicit choice, which keeps
  // the old "file it in the first folder" behaviour for older content scripts.
  | { type: "LOGIN_CANDIDATE"; username: string; password: string; faviconUrl?: string | null }
  | { type: "SAVE_DECISION"; username: string; password: string; mode: "save" | "update"; folderId?: string | null; faviconUrl?: string | null }
  // Redirect survival: the login banner lives in the page DOM, so a sign-in
  // redirect destroys it. The worker therefore retains the last prompted
  // capture (memory only) and each freshly loaded page re-asks for it.
  | { type: "CHECK_PENDING_SAVE" }
  // Confirm uses the worker-retained credentials — the post-redirect page has
  // no password field to read, and this avoids sending the secret back down.
  | { type: "CONFIRM_PENDING_SAVE"; folderId?: string | null; faviconUrl?: string | null }
  | { type: "DISMISS_PENDING_SAVE" }
  // OAuth sign-in memory: content reports offered providers + clicks; the
  // worker (which stamps origins from sender.tab.url) decides whether the
  // return trip looks like a completed SSO and answers whether to prompt.
  | { type: "OAUTH_CLICK"; provider: SsoProvider; offered: SsoProvider[] }
  | { type: "OAUTH_PAGE_STATE"; offers: SsoProvider[]; hasLoginForm: boolean; path: string; faviconUrl?: string | null }
  // `account` is the IdP account this sign-in used, or "" when the vault knows
  // no account for that provider (the worker then stores the provider alone).
  | { type: "SAVE_OAUTH_DECISION"; provider: SsoProvider; account: string; folderId?: string | null; faviconUrl?: string | null }
  | { type: "NEVER_ORIGIN" };

/** One destination option in the save card's folder picker. */
export interface SaveFolder {
  id: string;
  name: string;
}

/**
 * Fields every prompted save carries so the card can render the same shell:
 * what is being saved, where it will land, and which icon to show. The worker
 * already holds all of this while unlocked, so nothing extra is stored.
 */
interface SaveCardContext {
  /** Vault label (display only; the destination is the folder). */
  vaultName: string | null;
  /** Destination options in document order (empty when the vault has none). */
  folders: SaveFolder[];
  /** Preselected destination: first folder on a save, the item's folder on an update; null = Unfiled. */
  folderId: string | null;
  /** Display-only icon URL, already validated/sanitized by the worker. */
  faviconUrl: string | null;
}

export type SavePrompt =
  | { prompt: false }
  | ({
      prompt: true;
      mode: "save" | "update";
      origin: string;
      username: string;
    } & SaveCardContext);

/**
 * Whether a completed SSO sign-in on `origin` deserves a save prompt.
 * `accounts` are the vault's known accounts for that provider — the card
 * offers them as a choice because a password manager cannot observe which IdP
 * account was used. Empty means "save as Sign in with <provider>".
 */
export type OAuthSavePrompt =
  | { prompt: false }
  | ({
      prompt: true;
      provider: SsoProvider;
      origin: string;
      accounts: string[];
    } & SaveCardContext);

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
