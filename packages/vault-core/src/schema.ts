// Shared vault schemas — single source of truth for VaultItem and sync ops.
//
// Change from the web app's original shape: VaultItem gains a REQUIRED
// `origin` (canonical save-time origin, e.g. "https://accounts.example.com")
// plus optional `urls` (extra linked origins). Rationale: the old
// `{site, username}` free-text pair cannot answer "does this login belong to
// this origin?", so suggest/autofill cannot be phishing-resistant without it.
// No releases exist, so this changes the schema in place: no formatVersion,
// no migration, no legacy fallback — origin-less items are invalid.

import * as z from "zod";
import { canonicalizeOrigin } from "./origin.js";

// OAuth sign-in memory: one VaultItem holds every way to sign into a site —
// an optional stored password plus zero or more "Continue with X" methods.
// A login with both is a single item with multiple sign-in options; never two
// items for the same account.
export const SsoProviderSchema = z.enum(["google", "github", "apple", "microsoft", "custom"]);
export type SsoProvider = z.infer<typeof SsoProviderSchema>;

// One SSO sign-in method. `account` is the identity the IdP authenticates — an
// email, or a handle like "octocat" on GitHub — and it is the same thing the
// `username` field holds for a password login.
//
// The account MAY be empty, and that is a real state, not a placeholder: the
// extension cannot read an IdP's assertion, so it never learns which account a
// sign-in used. When the vault already holds accounts for that provider the
// save banner offers them as a choice; when it holds none, the sign-in is
// remembered as provider-only ("Sign in with GitHub") rather than dropped.
// An empty account means "a sign-in method exists, the account behind it is
// unknown" — renderers MUST label such a method by its provider and never
// print an empty username. `sub` is deliberately NOT stored: it is opaque,
// per-(issuer, client) scoped, and unusable by a human.
export const SsoSignInSchema = z.object({
  provider: SsoProviderSchema,
  account: z.string().trim().max(320),
});
export type SsoSignIn = z.infer<typeof SsoSignInSchema>;

// IdP host fragment → provider. Used by the extension's DOM detection
// (href to an IdP is the highest-confidence signal); kept here so web +
// extension can't drift. Substring match on the link hostname.
// Normalizers shared by client + extension so the document is written the same
// way everywhere. Kept here (pure, dependency-free) rather than in the client.
export function normalizeVaultName(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const cleaned = input.replace(/[\u0000-\u001f\u007f]/g, "").replace(/\s+/g, " ").trim();
  if (!cleaned || cleaned.length > MAX_VAULT_NAME_LENGTH) return null;
  return cleaned;
}

export function normalizeFolderName(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const cleaned = input.replace(/[\u0000-\u001f\u007f]/g, "").replace(/\s+/g, " ").trim();
  if (!cleaned || cleaned.length > MAX_FOLDER_NAME_LENGTH) return null;
  return cleaned;
}

export const OAUTH_IDP_HOSTS: Record<string, SsoProvider> = {
  "accounts.google.com": "google",
  "github.com": "github",
  "appleid.apple.com": "apple",
  "login.microsoftonline.com": "microsoft",
};

// Domains a provider's *accounts live on*, as opposed to the IdP host used by
// a sign-in button. A plain `github.com` login storing the handle `octocat` IS
// that person's GitHub account, so it must count as a candidate when the user
// signs in somewhere with "Continue with GitHub" — otherwise the only way to
// learn an account is to have saved an explicit SSO method first.
//
// Deliberately narrow: only domains where the account IS the login, never a
// broad parent like `google.com` (any Google property would qualify) — hence
// `mail.google.com` is listed explicitly instead. Subdomain match, so
// `gist.github.com` still counts as GitHub.
export const SSO_PROVIDER_ACCOUNT_DOMAINS: Record<string, SsoProvider> = {
  "github.com": "github",
  "gmail.com": "google",
  "googlemail.com": "google",
  "mail.google.com": "google",
  "outlook.com": "microsoft",
  "hotmail.com": "microsoft",
  "live.com": "microsoft",
  "icloud.com": "apple",
};

/**
 * The provider whose accounts live on this origin, or null. Uses the stored
 * canonical `origin` (never display text), and a parse failure is simply "not
 * one of ours" — never an error, since this only ever widens a suggestion.
 */
export function providerOfAccountOrigin(origin: string | undefined): SsoProvider | null {
  if (!origin) return null;
  let host: string;
  try {
    host = new URL(canonicalizeOrigin(origin)).hostname.toLowerCase();
  } catch {
    return null;
  }
  for (const [domain, provider] of Object.entries(SSO_PROVIDER_ACCOUNT_DOMAINS)) {
    if (host === domain || host.endsWith(`.${domain}`)) return provider;
  }
  return null;
}

export const VaultItemSchema = z.object({
  id: z.uuid(),
  site: z.string(),
  // THE identity of this login, present for every usable item. For a password
  // login it is the site's own username/email; for an SSO login it is the
  // account at the IdP (`me@gmail.com`, `octocat`). Both are the same thing —
  // the account this row is about — which is what lets one item carry both a
  // password and an SSO method. Absent only when the item has no identity to
  // name: a provider-only sign-in, or a discarded user-declined capture.
  // Consumers must use `item.username ?? ""`.
  username: z.string().optional(),
  // Optional: absent for SSO-only items (no secret exists). An item may carry
  // both a password and sso methods — that is one account with two ways in.
  password: z.string().optional(),
  // "Continue with X" methods on this login, each naming the account it
  // authenticates — or naming none, for a provider-only sign-in. Empty
  // (default) means password-only. No secret is ever stored for SSO — just the
  // provider + account + origin so clients can answer "how do I sign in here?"
  // and, when the account is known, "which account is that?".
  //
  // INVARIANT: when `sso` is non-empty and its first entry names an account,
  // `username` equals that account. One item = one account: the identity always
  // lives in `username`, `sso` only says which IdPs reach it. Capture relies on
  // this to decide whether a new sign-in joins this item or starts a new one.
  // A provider-only method (empty account) is the one exception: it carries no
  // identity, so such an item stores no `username` at all.
  sso: z.array(SsoSignInSchema).default([]),
  // Canonical origin captured at save time (scheme + host [+ non-default port]).
  // Optional during the M0 transition: the web add-item form does not capture
  // it yet (M1 wires it); extension writers always set it. Items without an
  // origin are valid but never origin-matched (rankOriginMatch → null).
  origin: z.string().optional(),
  // Additional origins the user explicitly linked to this login.
  urls: z.array(z.string()).optional(),
  // Favicon URL of the site captured at save time (the browser tab's own
  // icon first, else the page's `<link rel="icon">` href resolved absolute,
  // else `<origin>/favicon.ico`).
  // Display-only: never used for matching (rankOriginMatch ignores it), never
  // fetched by the extension worker — rendering surfaces load it with an
  // onError fallback to the letter avatar. Optional so pre-favicon items stay
  // valid; renderers derive `<origin>/favicon.ico` when absent.
  faviconUrl: z.string().trim().max(2048).optional(),
  // The folder this login lives in. Absent means "Unfiled" — a real state, not a
  // placeholder: items captured by the extension before folders existed and items
  // whose folder was deleted on another device both land here, and must render.
  folderId: z.uuid().optional(),
});

export type VaultItem = z.infer<typeof VaultItemSchema>;

// --- Account / SSO helpers --------------------------------------------------
// The shared rules behind "one item = one account". Both the web app and the
// extension call these so capture can never disagree about what belongs
// together. They are pure and dependency-free.

/**
 * Comparison key for an account string. IdP accounts are emails and handles,
 * which are case-insensitive in practice — `Me@Gmail.com` and `me@gmail.com`
 * are the same account and must not create two rows.
 */
export function normalizeAccount(account: string): string {
  return account.trim().toLowerCase();
}

/**
 * Whether this item represents the given account. Compares against `username`
 * (the canonical identity field) only: `sso[].account` mirrors it by the
 * invariant above, so a second comparison would be redundant.
 */
export function itemHasAccount(item: { username?: string }, account: string): boolean {
  const own = item.username;
  return !!own && normalizeAccount(own) === normalizeAccount(account);
}

/** True when the item already carries this exact sign-in method. */
export function hasSsoSignIn(
  item: { sso?: SsoSignIn[] },
  provider: SsoProvider,
  account: string,
): boolean {
  return (item.sso ?? []).some(
    (s) => s.provider === provider && normalizeAccount(s.account) === normalizeAccount(account),
  );
}

/**
 * Adds a sign-in method to a set, idempotently. Re-adding an existing
 * provider/account pair is a no-op (case-insensitive), so a capture that races
 * a manual edit converges instead of duplicating the row. Order is preserved.
 */
export function upsertSsoSignIn(
  existing: readonly SsoSignIn[],
  signIn: SsoSignIn,
): SsoSignIn[] {
  if (hasSsoSignIn({ sso: existing as SsoSignIn[] }, signIn.provider, signIn.account)) {
    return [...existing];
  }
  return [...existing, signIn];
}

/** Unique providers on an item, in first-seen order — for fill highlighting. */
export function ssoProvidersOf(item: { sso?: SsoSignIn[] }): SsoProvider[] {
  const seen: SsoProvider[] = [];
  for (const s of item.sso ?? []) {
    if (!seen.includes(s.provider)) seen.push(s.provider);
  }
  return seen;
}

/**
 * True when a method records no account — "Sign in with GitHub", identity
 * unknown. Such a method still tells a client HOW to sign in; it just cannot
 * say WHICH account, so UI must fall back to naming the provider.
 */
export function isProviderOnlySignIn(signIn: SsoSignIn): boolean {
  return normalizeAccount(signIn.account) === "";
}

/**
 * Every account the vault already knows for one provider, deduplicated
 * case-insensitively in first-seen order. This is the candidate list for a
 * completed SSO sign-in: the extension cannot observe which IdP account was
 * used, so it offers the ones already stored rather than guessing.
 *
 * An account qualifies two ways, because both are real knowledge the user
 * already has:
 *  1. an explicit sign-in method for that provider — the method's account, or
 *     the item's own identity when the method itself names none;
 *  2. an item hosted on one of the provider's account domains (see
 *     SSO_PROVIDER_ACCOUNT_DOMAINS) — a plain `github.com` login whose
 *     username is the handle.
 * Accounts are never invented: an item with no identity contributes nothing,
 * which is what keeps a provider-only method from being offered as a choice.
 */
export function ssoAccountsForProvider<
  T extends { username?: string; site?: string; origin?: string; sso?: SsoSignIn[] },
>(items: readonly T[], provider: SsoProvider): string[] {
  const seen = new Set<string>();
  const accounts: string[] = [];
  const add = (raw: string | undefined) => {
    const account = (raw ?? "").trim();
    if (!account) return;
    const key = normalizeAccount(account);
    if (seen.has(key)) return;
    seen.add(key);
    accounts.push(account);
  };
  for (const item of items) {
    for (const signIn of item.sso ?? []) {
      if (signIn.provider !== provider) continue;
      add(signIn.account || item.username);
    }
    // `site` is display text and never a match signal, so it is only consulted
    // when `origin` is missing (items captured before origins were stored).
    // Free text that isn't a host fails to parse and simply contributes
    // nothing — the worst case is a narrower list, never a wrong account.
    if (item.username && providerOfAccountOrigin(item.origin || item.site) === provider) {
      add(item.username);
    }
  }
  return accounts;
}

/**
 * Display identity for an item that may be provider-only. Password logins and
 * account-naming SSO logins lead with `username`; a provider-only item falls
 * back to naming the sign-in method itself ("Sign in with GitHub") so a row is
 * never blank. `providerPrefix` is the surface's phrasing of that fallback.
 */
export function ssoItemIdentity(
  item: { username?: string; sso?: SsoSignIn[] },
  providerLabel: (provider: SsoProvider) => string,
  providerPrefix = "Sign in with ",
): string {
  if (item.username) return item.username;
  const named = (item.sso ?? []).filter((s) => !isProviderOnlySignIn(s)).map((s) => s.account);
  if (named.length > 0) return named.join(" · ");
  const providers = ssoProvidersOf(item);
  if (providers.length === 0) return "";
  return `${providerPrefix}${providers.map(providerLabel).join(", ")}`;
}

/**
 * The item a newly captured sign-in method should join: same origin AND the
 * same account. Returns undefined when the account is new to that origin —
 * the caller then creates a separate item, because a different account is a
 * different set of data (see case F: personal and work Google on one site).
 */
export function findItemForAccount<T extends { origin?: string; username?: string }>(
  items: readonly T[],
  origin: string,
  account: string,
): T | undefined {
  return items.find((i) => i.origin === origin && itemHasAccount(i, account));
}

// --- Favicon helpers -------------------------------------------------------
// Favicons are display-only metadata (never a match signal, never a secret).
// Writers sanitize at save time so a weird icon can never block a save or
// quarantine an intent; renderers fall back to `<origin>/favicon.ico` when no
// stored URL exists and to the letter avatar when loading fails.

const FAVICON_MAX_LENGTH = 2048;

/** Returns a safe-to-store favicon URL, or undefined when unusable. */
export function sanitizeFaviconUrl(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > FAVICON_MAX_LENGTH) return undefined;
  // Only remote http(s) icons are stored: no javascript:/data:/chrome: URIs
  // (XSS / vault-bloat vectors), no relative URLs (unresolvable off-page).
  if (!/^https?:\/\/[^/\s]+(\/\S*)?$/i.test(trimmed)) {
    return undefined;
  }
  return trimmed;
}

/** Display fallback when an item stores no favicon: `<origin>/favicon.ico`. */
export function fallbackFaviconUrl(origin: string | undefined): string | undefined {
  if (!origin) return undefined;
  try {
    const url = new URL(origin);
    if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
    return `${url.origin}/favicon.ico`;
  } catch {
    return undefined;
  }
}

/** Effective icon URL for rendering: stored first, origin-derived fallback. */
export function faviconForItem(item: { origin?: string; faviconUrl?: string }): string | undefined {
  return sanitizeFaviconUrl(item.faviconUrl) ?? fallbackFaviconUrl(item.origin);
}

export const VAULT_DOCUMENT_FORMAT_VERSION = 1;

/**
 * The name a vault starts life with. Chosen during onboarding, then carried
 * inside the encrypted document — the server never sees it.
 */
export const DEFAULT_VAULT_NAME = "My Vault";

/** Longest accepted name, after trimming and whitespace collapse. */
export const MAX_VAULT_NAME_LENGTH = 48;

export const MAX_FOLDER_NAME_LENGTH = 48;

export const DEFAULT_FOLDER_NAME = "Personal";
// Fixed id for the folder every vault is born with. Must be a v4-shaped UUID so
// it survives FolderSchema's `z.uuid()` check; a known-answer test pins it.
export const DEFAULT_FOLDER_ID = "5b0e6a1c-0000-4000-8000-000000000001";

export const FolderSchema = z.object({
  id: z.uuid(),
  name: z.string().trim().min(1).max(MAX_FOLDER_NAME_LENGTH),
});
export type Folder = z.infer<typeof FolderSchema>;

// --- Folder views -----------------------------------------------------------
// Display-only helpers shared by the web app and the extension popup. Folders
// are labels, never identity: an item whose `folderId` is missing, or points at
// a folder that no longer exists, renders in "Unfiled" — a real bucket, not an
// error state. The bucket is never stored.
export const UNFILED_LABEL = "Unfiled";

/** Folder label for one item, or "Unfiled" when it has no live folder. */
export function folderNameFor(
  folders: readonly Folder[],
  item: { folderId?: string },
): string {
  const folder = folders.find((f) => f.id === item.folderId);
  return folder ? folder.name : UNFILED_LABEL;
}

/**
 * Items in one folder view. `folderId === null` means the Unfiled bucket:
 * items with no folderId OR a dangling one (deleted on another device).
 */
export function itemsInFolder(
  items: readonly VaultItem[],
  folders: readonly Folder[],
  folderId: string | null,
): VaultItem[] {
  if (folderId !== null) return items.filter((it) => it.folderId === folderId);
  const known = new Set(folders.map((f) => f.id));
  return items.filter((it) => !it.folderId || !known.has(it.folderId));
}

/** Counts for the folder list: total, unfiled, and per-folder. */
export function countByFolder(
  items: readonly VaultItem[],
  folders: readonly Folder[],
): { all: number; unfiled: number; byId: Record<string, number> } {
  const byId: Record<string, number> = {};
  let unfiled = 0;
  const known = new Set(folders.map((f) => f.id));
  for (const it of items) {
    if (!it.folderId || !known.has(it.folderId)) {
      unfiled++;
    } else {
      byId[it.folderId] = (byId[it.folderId] ?? 0) + 1;
    }
  }
  return { all: items.length, unfiled, byId };
}

export interface DecryptedVault {
  formatVersion: number;
  vaultId: string;
  /** User-facing label. Never the identity: `vaultId` still is. */
  name: string;
  folders: Folder[];
  items: VaultItem[];
}

/**
 * The active session, scoped to a single vault. There is no account/user object
 * — `vaultId` is the only identity and the session cookie carries only it.
 */
export interface SessionState {
  vaultId: string;
  cryptoVersion: number;
}

/**
 * Material needed to re-derive the vault key locally when unlocking after a
 * lock. All values are zero-knowledge-safe (salt/iterations/wrapped key are
 * things the server already knows).
 */
export interface LockMetadata {
  salt: string;
  iterations: number;
  vaultKeyWrap: string;
  vaultKeyWrapIv: string;
}

// NOTE: the shared `AuthState` label union ("not_authenticated" | "locked" |
// "unlocked") that used to live here has been removed. It described the *web
// app's* routing and key handling, which the MV3 extension does not share (no
// landing/lock/home routes, no first-run "no vault" state). The web app now
// routes on `VaultState` in apps/client/src/lib/state/vault-state.ts, a
// discriminated union that carries the vault id and key so they cannot
// disagree.

// --- Sync op payloads ----------------------------------------------------
// Create carries a full VaultItem. Update carries only changed fields so two
// devices editing different fields of the same entry both survive a merge.
// Origin/urls/faviconUrl ride the same per-field LWW path as
// site/username/password.

/**
 * Document-level rename. Trimmed and bounded here as well as in the UI: an
 * intent payload is user-controlled storage, and a malformed one must be
 * quarantined rather than written into the document.
 */
export const RenameVaultSchema = z.object({
  name: z.string().trim().min(1).max(MAX_VAULT_NAME_LENGTH),
});
export type RenameVault = z.infer<typeof RenameVaultSchema>;

export const CreateFolderSchema = z.object({
  id: z.uuid(),
  name: z.string().trim().min(1).max(MAX_FOLDER_NAME_LENGTH),
});
export type CreateFolder = z.infer<typeof CreateFolderSchema>;

export const RenameFolderSchema = z.object({
  id: z.uuid(),
  name: z.string().trim().min(1).max(MAX_FOLDER_NAME_LENGTH),
});
export type RenameFolder = z.infer<typeof RenameFolderSchema>;

export const DeleteFolderSchema = z.object({
  id: z.uuid(),
});
export type DeleteFolder = z.infer<typeof DeleteFolderSchema>;

export const UpdateVaultItemSchema = z.object({
  id: z.uuid(),
  fields: z.object({
    site: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    sso: z.array(SsoSignInSchema).optional(),
    origin: z.string().optional(),
    urls: z.array(z.string()).optional(),
    faviconUrl: z.string().trim().max(2048).optional(),
    folderId: z.uuid().optional(),
  }),
});
export type UpdateVaultItem = z.infer<typeof UpdateVaultItemSchema>;

export const DeleteVaultItemSchema = z.object({
  id: z.uuid(),
});
export type DeleteVaultItem = z.infer<typeof DeleteVaultItemSchema>;

export const CreateVaultItemSchema = VaultItemSchema;
export type CreateVaultItem = z.infer<typeof CreateVaultItemSchema>;

// --- Vault document parse / serialize ---------------------------------------
// Single decoder + encoder shared by the web app and the extension. Keeping both
// here is what stops a field (today `folders`, tomorrow something else) from
// being silently dropped by a writer that rebuilds `{ name, items }`.

export interface VaultDocument {
  name: string;
  folders: Folder[];
  items: VaultItem[];
}

export function parseVaultDocument(plain: string): VaultDocument {
  let parsed: unknown;
  try {
    parsed = JSON.parse(plain);
  } catch {
    parsed = {};
  }
  if (typeof parsed !== "object" || parsed === null) parsed = {};
  const obj = parsed as Record<string, unknown>;

  const name = normalizeVaultName(obj.name) ?? DEFAULT_VAULT_NAME;

  const rawItems: VaultItem[] = Array.isArray(obj.items) ? (obj.items as VaultItem[]) : [];

  // Legacy discriminator: a document written before folders existed has NO
  // `folders` key at all. Key present (even `[]`) is trusted verbatim so an
  // intentionally emptied list never resurrects "Personal".
  const hasFoldersKey = Object.prototype.hasOwnProperty.call(obj, "folders");
  if (!hasFoldersKey) {
    const folders: Folder[] = [{ id: DEFAULT_FOLDER_ID, name: DEFAULT_FOLDER_NAME }];
    const items = rawItems.map((it) =>
      it && typeof it === "object" && !(it as { folderId?: unknown }).folderId
        ? { ...it, folderId: DEFAULT_FOLDER_ID }
        : it,
    );
    return { name, folders, items };
  }

  const folders: Folder[] = Array.isArray(obj.folders)
    ? (obj.folders as unknown[]).filter((f): f is Folder => FolderSchema.safeParse(f).success)
    : [];

  return { name, folders, items: rawItems };
}

export function serializeVaultDocument(doc: VaultDocument): string {
  return JSON.stringify({ name: doc.name, folders: doc.folders, items: doc.items });
}

// --- Server API shapes (shared so web + extension can't drift) ------------

export type VaultResponse = {
  vault: {
    vault: string;
    vaultiv: string;
    iterations: number;
    version: number;
    crypto_version: number;
    vault_key_wrap: string | null;
    vault_key_wrap_iv: string | null;
  };
};

export type UpdateVaultRequest = {
  vault: string;
  vaultiv: string;
  version: number;
  crypto_version?: number;
  vault_key_wrap?: string;
  vault_key_wrap_iv?: string;
};

export type UpdateVaultResponse = {
  vault: string;
  vaultiv: string;
  iterations: number;
  version: number;
  crypto_version: number;
  vault_key_wrap: string | null;
  vault_key_wrap_iv: string | null;
};
