# Client Sync Architecture

How a vault edit travels from a click in the UI to durable ciphertext on the
server, and how a peer (another tab, the browser extension) learns that the
vault locked. Everything here is **local-first**: the client always has a
durable, encrypted queue, and the network is an optimisation, not a
dependency.

Scope: `apps/client/src/lib/sync/`. Merge policy itself lives in
`packages/vault-core/src/merge.ts` (shared with the MV3 extension) and is
documented in `apps/client/conflict-resolution.md`.

---

## 1. The write path — edit → intent → sync

```
  User clicks "Save"
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ home/index.tsx  handleCreate / handleUpdate / handleDelete    │
│   builds a VaultItem or a partial UpdateVaultItem             │
└───────────────────────────────────────────────────────────────┘
        │
        ▼
   encrypt(JSON.stringify(op), vaultKey)        AES-GCM, fresh 12-byte IV
        │  ── plaintext exists only here, in memory ──
        ▼
┌───────────────────────────────────────────────────────────────┐
│ createIntent(operation, { payload, payloadIv, deviceId })     │
│   INSERT INTO intent (id, operation, payload, payload_iv,    │
│                       device_id, base_version, created_at)   │
│   ⚡ DURABLE — survives reload, crash, offline                │
└───────────────────────────────────────────────────────────────┘
        │
        ├──► optimistic Zustand update (add/update/deleteVaultItem)
        │        └──► UI already shows the change
        │
        └──► syncScheduler.requestSync("intent-created")
                     │
                     ▼
        ┌────────────────────────────────┐
        │  SyncScheduler (coalescing)   │  running / pending flags
        │  sets isSyncing in the store   │  re-runs once if a trigger
        └────────────────────────────────┘  fired while running
                     │
                     ▼
              sync()   ← index.ts
```

`sync()` never trusts the in-memory vault as durable state. The intent row is
the record of truth; Zustand is just a render cache.

---

## 2. The sync engine — `index.ts`

One run, bounded at `MAX_SYNC_RETRIES = 3`:

```
  ┌─ preconditions ────────────────────────────────────────────┐
  │ vaultKey && session present?   else bail (locked ⇒ no keys)│
  │ pin syncVaultId                                          │
  │ sessionChanged() guard: abort if the session's vault moved │
  └───────────────────────────────────────────────────────────┘
        │
        ▼
  ┌─ load server snapshot ────────────────────────────────────┐
  │ GET /get_vault → decrypt(response.vault, .vaultiv, key)  │
  │ network error?  → return quietly (offline is a normal    │
  │                   state; intents stay queued)             │
  └───────────────────────────────────────────────────────────┘
        │
        ▼
  ┌─ read local state ────────────────────────────────────────┐
  │ getlocalVaultVersion()      client_state.vault_version    │
  │ fetchPendingIntents()       WHERE synced=0 AND error IS   │
  │                             NULL  ORDER BY created_at ASC │
  └───────────────────────────────────────────────────────────┘
        │
        ├── no pending intents ──► localVersion ≠ serverVersion?
        │                              │            │
        │                             yes          no → return
        │                              ▼
        │                     adoptServerSnapshot (pull-only path)
        │
        ▼ (intents pending)
  ┌─ merge ───────────────────────────────────────────────────┐
  │ mergeVault(serverItems, pendingIntents, vaultKey)         │
  │   deterministic order: created_at, then id                │
  │   per-op policy in packages/vault-core/src/merge.ts        │
  │                                                          │
  │   → { items, changed, resolvedIds, quarantinedIds }       │
  │                                                          │
  │ quarantinedIds → markIntentError (set error, stops        │
  │                  being selected by fetchPendingIntents)   │
  └───────────────────────────────────────────────────────────┘
        │
        ├── changed === false ──► adoptServerSnapshot
        │                         markIntentsSynced(resolvedIds)
        │                         return
        ▼
  ┌─ push ────────────────────────────────────────────────────┐
  │ encrypt(JSON.stringify({ items: merged.items }), key)    │
  │ POST /update_vault { vault, vaultiv, version: serverVer } │
  │                                                          │
  │   network error → return (queue survives)                │
  │   409 VERSION_CONFLICT → continue  (retry loop)          │
  │   other error → log + return                             │
  └───────────────────────────────────────────────────────────┘
        │
        ▼
  ┌─ confirm & adopt ─────────────────────────────────────────┐
  │ loadItemsFromResponse(response, key)                     │
  │   decrypt the server's RESPONSE — never trust local guess │
  │ adoptServerSnapshot(items, response.version)             │
  │ markIntentsSynced(merged.resolvedIds)                    │
  └───────────────────────────────────────────────────────────┘
```

### Server-side concurrency control

`apps/server/src/endpoints/update_vault.rs` makes the push atomic:

```sql
UPDATE vault
   SET vault = ?, vaultiv = ?, version = version + 1, ...
 WHERE id = ? AND version = ?     -- the version the client pushed against
```

`rows_affected == 0` means a peer won the race → `409 VERSION_CONFLICT` → the
client loops, re-reads the snapshot, and re-merges. There is no read-then-write
window.

---

## 3. Triggers — what starts a run

| Trigger | Source | Mounted? |
|---|---|---|
| `intent-created` | `home/index.tsx` after every create/update/delete | ✅ |
| `forced` | manual | — |
| `window-focus` | `use-sync-triggers.ts` | ❌ **not mounted** |
| `network-reconnect` | `use-sync-triggers.ts` | ❌ **not mounted** |

`use-sync-triggers.ts` exists and is correct but is not called from
`_layout.tsx`, so focus and reconnect do not currently trigger a sync.

---

## 4. Cross-surface lock — `use-session-sync.ts` + `session-channel.ts`

Distinct from data sync: this is about **wiping keys when someone else locks**.

```
  Web app                 Server                    Extension
  ───────                 ──────                    ─────────
  lockVaultNow() ──POST /lock──►  vault.lock_epoch += 1
       │                              │
       │                              ├── GET /session ──► epoch > mine?
       │                              │                     │ yes
       │                              │                     ▼
       │                              │              lock() — wipe memory
       │
       └── postSessionEvent("locked") ──► BroadcastChannel (same origin)
                                                │
                                          sibling web tabs
                                          wipe + route /lock
```

- **Tab ↔ tab** is instant and free: `BroadcastChannel("voult:session")`, with a
  `localStorage` storage-event fallback (`session-channel.ts:57`). Only
  `{ type, vaultId, lockEpoch }` crosses — no secrets.
- **Web ↔ extension** cannot share a channel (different origin), so it routes
  through the monotonic `vault.lock_epoch` on the server. Both sides
  check-on-use: web on focus/visible/online, extension on popup open, before any
  credential release, and on a 1-minute alarm.
- **Unlock never propagates.** Each surface re-unwraps locally with its own
  device key. The epoch only ever moves forward.
- **Single-vault invariant:** if `GET /session` returns a different `vault_id`
  than local state, this surface tears down and goes unauthenticated rather than
  adopting the new vault unlocked.

---

## 5. Storage layout

| Store | Namespace | Contents |
|---|---|---|
| SQLite OPFS | `file:voult-<vaultId>.db` | `intent`, `client_state` |
| `intent` | per-vault DB | encrypted payload + iv, operation, device id, base_version, synced, error |
| `client_state` | per-vault DB | `vault_version` (sync's only writer), `vaultId` |

One OPFS file per vault, so a pending intent from another vault is physically
unreachable rather than merely filtered.

---

## Invariants

Breaking any of these breaks the security model, not just correctness:

1. **Never write a plaintext intent.** Encryption happens before `createIntent`.
2. **Never send plaintext to the server.** Transport is one whole-blob
   ciphertext per push — never per-item ops.
3. **Never mark intents synced before a decryptable server snapshot is
   confirmed.** `loadItemsFromResponse` is the proof.
4. **Sync is the only writer of `client_state.vault_version`.** UI code must not
   write it.
5. **Pin the vault for the whole run.** A mid-flight session change aborts
   rather than writing another vault's data.
6. **Offline is not an error.** Network failures return quietly and leave the
   queue intact.
7. **One bad intent must not block the rest** — malformed payloads quarantine
   individually.

---

## File map

| File | Role |
|---|---|
| `index.ts` | The sync engine: fetch → merge → push → confirm |
| `merge.ts` | Thin adapter delegating to `@voult/vault-core` |
| `sync-scheduler.ts` | Coalescing queue, `isSyncing` status |
| `use-sync-triggers.ts` | focus/online triggers — **not currently mounted** |
| `use-session-sync.ts` | `lock_epoch` convergence, vault-switch teardown |
| `session-channel.ts` | Same-origin tab ↔ tab BroadcastChannel |
| `remote.ts` | **Removed.** `getVaultRemote` / `GoogleRemote` / `isGoogleRemoteError` had no importers. The model settled on: **the server is the write authority, Drive is the disaster-recovery copy.** The client pulls only `/get_vault`; the server re-writes the Drive copy after each CAS via `apps/server/src/google/mirror.rs`. |
| `type.ts` | Re-exports op schemas from `@voult/vault-core` |