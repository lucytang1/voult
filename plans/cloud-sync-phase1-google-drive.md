# Phase 1: Multi-Device Vault Sync via Google Drive

Status: draft
Scope: **vault item sync only** (+ minimal vault metadata required to bootstrap login on new devices). Signup remains email + password with no Google step (email verification skipped for Phase 1). Password change/rotation, other providers, sharing, and attachment sync are out of scope (later phases).

---

## 1. Goal

A user signs up as they do today (email + password), then optionally connects Google Drive. Once connected, devices signed into the same Google account propagate vault item changes between each other. Item creates/updates/deletes made on one device appear on the others via Google Drive, with zero-knowledge semantics preserved: Drive stores only ciphertext and non-sensitive KDF metadata. No voult server involved.

## 2. Non-goals (Phase 1)

- Dropbox / OneDrive / WebDAV adapters (interface will be built to allow them)
- Master password change propagation / remote logout
- Vault sharing, attachments, multiple vaults per account
- Real-time push (polling + focus/reconnect triggers only)
- Native/mobile targets (web-only, matching current app)

## 3. Why this fits the current architecture

The existing sync engine (`apps/client/src/lib/sync/index.ts`) already treats the server as an opaque encrypted-blob store whose only job is version CAS. Everything else — intent queue (`intent` table), deterministic replay `(created_at, id)` in `sync/merge.ts`, per-field LWW, quarantine of undecryptable intents, whole-blob AES-GCM encryption, PBKDF2/HKDF key hierarchy — is client-side and storage-agnostic. Phase 1 swaps the *transport*, not the sync model.

## 4. Storage layout on Google Drive

Use the Drive **`appDataFolder`** space (`drive.appdata` scope): hidden from the user's file list, not indexed, scoped to our app. Simplest option — no folder-picker UI, no risk of users deleting/moving files. Trade-off: the user cannot inspect/back up the raw files from Drive UI (documented to the user). A user-visible-folder mode can be added later as an alternative backend config.

```
appDataFolder/
  voult-meta.json          ← plaintext, non-sensitive (see §5)
  voult-vault.enc          ← opaque ciphertext blob (see §5)
```

Two files, fixed names. One voult identity per Google account (Phase 1). If `voult-meta.json` is absent on login → treat as "no account here" (offer signup); if `voult-vault.enc` is missing while meta exists → error state requiring re-setup (do not silently recreate).

### Concurrency model (important)

Drive has **no conditional/atomic write** (no CAS endpoint). Two devices doing read-modify-write concurrently can clobber each other — the classic limitation of cloud-drive sync (Enpass has the same window; they accept it).

Mitigation strategy for Phase 1:
1. Before writing, record the file's `headRevisionId` (returned by `files.get`, `files.update`).
2. After `files.update`, immediately re-read the file's latest revision. If our write isn't the head revision, another device wrote concurrently → run the reconcile loop again (our intents are still pending locally, `mergeVault` is idempotent, so re-running is safe).
3. Retry bounded by the existing `MAX_SYNC_RETRIES`.

This shrinks the loss window from "between read and write" to "between update and revision-check" (sub-second), and any loss is detected rather than silent. Full elimination (per-device snapshot/intent files + compaction) is deliberately deferred — see §11.

## 5. File formats

### `voult-meta.json` (plaintext — contains no secrets)

```jsonc
{
  "format": 1,
  "email": "user@example.com",        // display/routing only; NOT an auth factor
  "crypto_version": 2,
  "salt": "<b64>",                    // PBKDF2 salt
  "iterations": 60000,
  "auth_verifier": "<b64>",           // HMAC-SHA256("auth-v1||static", authKey) — same value the server stored as user_key
  "updated_at": 1730000000000
}
```

Purpose: lets a fresh device perform full offline-capable login (derive keys from password, verify `auth_verifier`, unwrap the vault key) with no server. Anyone who steals this file gets salt + verifier + ciphertext — i.e., an offline brute-force target identical to any encrypted-vault file (KeePass/Enpass equivalent). Acceptable; documented. Iterations should be raised in a later phase (Argon2id candidate); out of scope here.

### `voult-vault.enc`

JSON envelope, base64 fields (mirrors today's server-side `vault` row so crypto code is untouched):

```jsonc
{
  "format": 1,
  "version": 42,                       // monotonically bumped on every successful local push; advisory (merge correctness does NOT depend on it)
  "cipher": "<b64 AES-GCM ciphertext>",
  "iv": "<b64 12-byte IV>"
}
```

Decrypted plaintext = `{ "items": VaultItem[] }` — unchanged.
The **vault key** stays wrapped how? Phase 1 simplification: the vault key wrap currently lives server-side (`vault_key_wrap`). In Drive mode, store the wrapped vault key inside `voult-meta.json`:

```jsonc
{
  ...,
  "vault_key_wrap": "<b64>",
  "vault_key_wrap_iv": "<b64>"
}
```

These are ciphertext under the password wrapping key — safe in the plaintext-metadata file (same trust level as the verifier). This keeps `meta.json` self-sufficient for bootstrapping and leaves `vault.enc` purely item data.

## 6. Google OAuth (browser)

No OAuth infrastructure exists in the client today — this is net-new.

- Flow: **Authorization Code + PKCE**, using Google Identity Services (loaded via script tag; must be COEP-compatible with the existing OPFS headers — load GIS in credentialless mode or serve with `COEP: credentialless` if required; verify during implementation).
- Scopes requested: `https://www.googleapis.com/auth/drive.appdata` (plus `openid email`).
- Tokens:
  - Access token (~1h TTL): kept in memory only; injected by a small axios/fetch wrapper in the Drive adapter.
  - Refresh token: **encrypted with the existing IndexedDB device key** (`crypto/device-key.ts`) before persistence, namespaced per-user like `DeviceEnvelopeRecord`. Plaintext refresh tokens never hit SQLite/localStorage.
- Token lifecycle module: `src/lib/cloud/google-auth.ts`
  - `connectGoogle(): Promise<GoogleTokens>` — popup/redirect flow
  - `getAccessToken(): Promise<string>` — transparent refresh on expiry
  - `revokeAndForget()` — called on logout/unlink (Drive API `revoke` endpoint + delete encrypted record)
- We never see the Google password; tokens never leave the device unencrypted. Same stance as Enpass.

## 7. Transport abstraction

Introduce a minimal interface so the existing server remains usable (dev fallback) and future providers plug in:

```ts
// src/lib/cloud/types.ts
export interface CloudStore {
  readonly provider: "google-drive" | "local-server";
  // Metadata (small JSON, plaintext-safe)
  readMeta(): Promise<VoultMeta | null>;          // null = no account
  writeMeta(meta: VoultMeta, expect?: MetaStamp): Promise<MetaStamp>;
  // Vault blob (opaque ciphertext)
  readVault(): Promise<{ bytes: Uint8Array; stamp: CloudStamp } | null>;
  writeVault(bytes: Uint8Array, expect: CloudStamp): Promise<{ stamp: CloudStamp }>;
}
export type CloudStamp =
  | { kind: "drive"; headRevisionId: string }
  | { kind: "server"; version: number };
```

Implementations:
- `src/lib/cloud/google-drive.ts` — Drive REST v3 via fetch (`files.list` on appDataFolder once at connect to resolve file IDs, then `files.get`/`files.update` with `uploadType=media`; `headRevisionId` from responses).
- Existing axios calls (`queries/vault/query.ts`) stay as-is behind a thin `server-store.ts` adapter (or simply remain the default path when `EXPO_PUBLIC_SYNC_BACKEND !== "drive"`).

Backend selection: `EXPO_PUBLIC_SYNC_BACKEND=server|drive` (default `server`) so current dev flow is unaffected until Drive mode is switched on.

## 8. Sync algorithm changes

`sync/index.ts` gains a Drive-mode variant (or the same function parameterized by `CloudStore`). Drive-mode loop:

```
1. guard: vaultKey && session && backend === drive   (session pinning kept as-is)
2. remoteVault = store.readVault()
3. if no pending intents:
     if remote.stamp changed since lastSeenStamp → adopt snapshot (existing adoptServerSnapshot path)
     done
4. merged = mergeVault(remoteItems, pendingIntents, vaultKey)      // unchanged
5. quarantine/markSynced as today                                  // unchanged
6. if merged.changed:
     bytes = encrypt(JSON.stringify({items: merged.items}), vaultKey)
     envelope = { format: 1, version: localVersion+1, cipher, iv }
     { stamp } = store.writeVault(envelopeBytes, expectedStamp)
     verifyHeadRevision(stamp)  // §4 concurrency check; on failure, loop (bounded retries)
7. markIntentsSynced(merged.resolvedIds)
8. persist lastSeenStamp in client_state ("cloud_stamp") alongside vault_version
```

Notes:
- `version` becomes advisory in Drive mode (no server enforces CAS). Merge correctness continues to rest on idempotent intent replay, exactly as `conflict-resolution.md` specifies.
- Triggers unchanged (`use-sync-triggers.ts`: focus + online). Add an optional low-frequency poll timer (e.g., every 60s while unlocked) that cheaply compares the vault file's `headRevisionId` and requests a sync only on change.
- Session-pinning / abort-mid-run guards are preserved verbatim.
- While Google is not connected, sync is disabled entirely; the intent queue keeps buffering mutations locally so nothing is lost before/without cloud sync.

## 9. Auth flow changes

Signup stays exactly as users know it: **email + password only, no Google step** (email verification skipped in Phase 1). Google is connected *after* signup as an opt-in "enable cloud sync" action.

### Signup (first device) - no Google involved

`signupFlow` gains a **local mode** branch (gated by backend flag). No server calls at all:

1. Generate salt/vault key/wraps exactly as today (client-side).
2. Derive identity locally: `userId = uuidv5(DRIVE_NAMESPACE, email)` (rationale under Login below) so per-user OPFS DB / IndexedDB namespacing works unchanged.
3. Create starter vault, persist session in zustand + device envelope in IndexedDB.
4. Persist KDF params (`salt`, `iterations`) + `auth_verifier` + wrapped vault key in a **local profile record** mirroring `voult-meta.json`, stored with device secrets - there is no server to hold them anymore.
5. User lands in the app with a working local-only vault; sync is disabled ("cloud not connected").

### Connect Google (post-signup, opt-in)

A settings/onboarding action "Enable cloud sync via Google Drive":

1. Connect Google (`connectGoogle()`); persist encrypted refresh token.
2. `readMeta()` -> if a meta file already exists, refuse with "this Drive already holds a voult account" (offer login instead) - prevents accidental overwrite of another account's data.
3. Upload `voult-meta.json` (built from the local profile record) then `voult-vault.enc`.
4. Enable sync triggers/polling; run an initial sync.
5. Idempotent/re-runnable: re-connecting on a device that already has tokens just refreshes state.

### Login (any device)

Two cases:

**a) Device has the local profile** (signed up here): identical to today minus server calls - derive keys from password against the *local* profile record, verify verifier (constant-time compare), unwrap vault key, open DB, hydrate. If Google is not yet connected, app runs local-only until connected.

**b) Fresh device**: user enters email + password; no local profile found -> prompt "This vault syncs via Google Drive - sign in with Google":

1. Connect Google.
2. `readMeta()` -> null => error "No voult account found on this Drive account" (user either never enabled cloud sync, or picked the wrong Google account).
3. Sanity-check `meta.email` matches the entered email (mismatch -> warn but allow; email is display/routing only, not an auth factor).
4. Derive auth/wrapping keys from password + meta's salt/iterations.
5. Verify `computeAuthVerifier(authKey)` === meta.auth_verifier -> wrong password = generic failure (no server oracle; constant-time compare).
6. Unwrap vault key from `meta.vault_key_wrap` (replaces `fetchVault`-based unwrap).
7. Open per-user local DB using `userId = uuidv5(DRIVE_NAMESPACE, meta.email)` - stable across devices, so the same Google account maps to the same OPFS DB everywhere. Store `SessionState.user = { id: that uuid, email, cryptoVersion }` - downstream code (teardown, envelopes, DB naming) needs no changes beyond this derivation.
8. Read vault, decrypt, hydrate. Offer/persist the Google connection for future syncs.

### Logout / teardown

`auth/teardown.ts` extended: additionally revoke-or-forget Google tokens (ask user: "unlink this device" vs "keep token for faster unlock"). Local DB, envelopes, zustand wipe logic unchanged. Closing the tab without logout naturally keeps the encrypted refresh token for next time (same UX as staying logged in today via cookie).

### What disappears in Drive mode

- `/register`, `/auth`, `/logout`, `/session_status`, `/get_crypto_params`, `/get_vault`, `/update_vault` calls — all replaced by `CloudStore` + meta-based login. Server mode remains available behind the flag for development.

## 10. Implementation checklist

Ordered, roughly independently testable:

1. **Types & stamps** — `src/lib/cloud/types.ts`, meta/envelope schemas + encode/decode helpers with unit tests.
2. **Local profile record** — persist/read KDF params + verifier + wraps locally at signup/login (replaces `/get_crypto_params` and server-stored wraps); identity helper `uuidv5(email)` wired into session creation.
3. **Google auth module** — `google-auth.ts` (PKCE flow, token cache, refresh, revoke), COEP compatibility check for GIS script loading.
4. **Drive adapter** — `google-drive.ts` implementing `CloudStore` against Drive REST v3 (appDataFolder resolve, read/write both files, head-revision capture + post-write verification). Testable manually against a real account early.
4. **Auth flows** — local-mode branch in `signupFlow`; two-case `passwordLoginFlow`; "Connect Google" post-signup action (upload meta + vault, enable sync); extend `teardown.ts` for token cleanup.
5. **Sync** — Drive-mode sync loop in `sync/index.ts` (or sibling `sync/drive.ts` reusing `mergeVault`, scheduler, triggers); add `cloud_stamp` to `client_state`; add poll timer hook.
6. **Backend flag** — env gating in http layer / flow entry points; default remains `server`.
7. **UI** — settings entry point "Enable cloud sync via Google Drive"; fresh-device login prompt; sync-status surface reuses existing `setSyncStatus`; error states for (a) Drive unreachable/quota, (b) no-account-on-drive, (c) corrupt/missing files.
8. **Docs** — update `architecture.md`, `conflict-resolution.md` (add Drive concurrency section), AGENTS.md gotchas (COEP/GIS note).

## 11. Known limitations accepted in Phase 1

| Limitation | Why accepted | Later fix |
|---|---|---|
| Sub-second lost-update window on concurrent writes | Bounded, detectable via revision check; matches industry norm (Enpass/KeePass-over-Drive) | Per-device snapshot files + compaction (§12) |
| Offline brute-force possible against stolen Drive files | Inherent to file-based E2EE vaults | Raise iterations / Argon2id |
| No instant cross-device logout on password change | No push channel | Phase 2 (meta.crypto_version bump + forced re-auth on decrypt failure) |
| Single vault per Google account | Scope discipline | Multi-vault folders later |
| Refresh token lives in browser storage (encrypted) | Best available in web platform | Desktop/native shell later |

## 12. Future phases (not in this plan)

- **Phase 2**: master-password change + remote logout (rewrite meta with new wraps + bump `crypto_version`; other devices force re-login on unwrap failure).
- **Phase 3**: per-device sync files (`intents-<deviceId>.enc`) eliminating the write-race entirely, with periodic compaction into a base snapshot — natural evolution since the `intent` table already exists per-device.
- **Phase 4**: additional providers (Dropbox, OneDrive, WebDAV, plain folder) behind `CloudStore`; user-visible folder mode.

## 13. Testing plan

- Unit: meta/envelope codecs, local profile record round-trip, uuidv5 identity stability, stamp comparison logic.
- Integration (manual, two browser profiles + one Google account):
  0. Signup (no Google) works local-only; "Connect Google" uploads meta + vault; disconnect/reconnect is idempotent.
  1. Device A signup → Device B login sees starter vault.
  2. Create/edit/delete on each side interleaved; assert convergence (per-field LWW cases from `conflict-resolution.md` §5).
  3. Kill network mid-edit on B → edit on A → restore → assert B catches up with intents intact.
  4. Simulated write race (pause B mid-sync via debugger) → revision check detects, retry converges.
  5. Wrong password on B → clean failure, no partial state.
  6. Logout/unlink → tokens revoked, local artifacts wiped, re-login works.
- Regression: run with `SYNC_BACKEND=server` and confirm existing flows untouched.
