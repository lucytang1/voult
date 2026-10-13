# Client Sync Architecture

How a vault edit travels from a click in the UI to durable ciphertext on the
server, and how a peer (another tab, the browser extension) learns that the
vault locked. Everything here is **local-first**: the client always has a
durable, encrypted queue, and the network is an optimisation, not a
dependency.

Scope: `apps/client/src/lib/sync/`. Merge policy itself lives in
`packages/vault-core/src/merge.ts` (shared with the MV3 extension) and is
documented in `apps/client/conflict-resolution.md`.

§1–§5 describe the client-side engine. §6 describes the one thing the client
does **not** do: the cloud-provider copy is written by the *server*, out of band,
after the CAS commits — see `apps/server/src/cloud/mirror.rs`.

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
  than local state, this surface tears down and deselects rather than adopting the
  new vault unlocked. A user-initiated switch instead goes through
  `switchVaultOpen()`, which commits the new selection atomically.
- **Sync pins the selection, not the session.** `sync()` captures
  `captureSelectionEpoch()` and aborts if it changed — including an A→B→A round
  trip that an id comparison would miss. Pinning on `session` would be wrong:
  session loss (M2) nulls the session while the vault stays selected.

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

## 6. Cloud providers — the disaster-recovery copy

Everything above is about getting ciphertext into the `vault` row on the server.
This section is about what happens *after* that row is committed. It is
deliberately the smallest part of the sync system: one caller
(`/update_vault`), one spawned task, zero client involvement.

### 6.0 The model in one line

> **The server is the write authority. the provider is the disaster-recovery copy.**

```
   client sync()                     server                          cloud provider
   ─────────────                     ──────                          ────────────
   POST /update_vault ──────────►  ① SELECT vault                    (never consulted
   { vault, vaultiv, version: V }    ② UPDATE vault SET vault=?,     by the write path)
                                     version=version+1
                                     WHERE id=? AND version=V
                                     └ rows_affected == 0 → 409, return early
                                     ③ COMMITTED at V+1   ◄── the only truth
                                     ④ mark_pending()       (local DB, awaited)
                                     ⑤ spawn_after_commit() (returns immediately)
                                     ⑥ 200 { version: V+1 }
   loadItemsFromResponse ────┘
   decrypts the 200 body,
   markIntentsSynced()
   (never learns anything
    about Drive)

                                        ┌────────────── detached, off the request path
   …meanwhile, in the background:        │ mirror_once(): load binding → load vault →
                                         │ UpToDate? → package::build → token → status
                                         │ mirroring → resolve CAS baseline → replace_vault
                                         └──────────────────┬───────────────────────────────
                                                                │ PATCH /upload/drive/v3/files/{id}
                                                                │ conditional on remote_revision
                                                                ▼
                                                          cloud_binding watermark advances
```

### 6.1 The client never writes Drive during sync

`apps/client/src/lib/sync/` contains no reference to Drive, Google, a package,
or a mirror — `sync/index.ts` ends at `loadItemsFromResponse` (`index.ts:160`).
Consequences worth stating explicitly:

- A provider outage **cannot** fail a sync run, produce a retry loop, or hold an
  `intent` row un-synced. `sync()` only ever sees `200` / `409` / network errors.
- The `/update_vault` response carries no Drive field, so there is no
  provider-shaped failure for the client to handle.
- The only client→provider calls left are **enrollment**
  (`cloud/enableSync.ts` → `POST /cloud/vaults/create`), **restore**
  (`lib/vault/import.ts` → `GET /cloud/vaults/read`), **binding upsert**
  (`POST /cloud/binding`, used after an import), and the explicit
  **"Back up now"** action (`POST /cloud/vaults/mirror`). The provider
  adapter's `replaceVault` / `deleteVault` (`cloud/api.ts:95`, `:118`)
  exist but are not on any sync path.

### 6.2 The commit-time handoff (`update_vault.rs:144-155`)

```rust
let mirror_pool = pool.get_ref().clone();
let mirror_vault_id = vault_id.clone();
crate::cloud::mirror::mark_pending(&mirror_pool, &mirror_vault_id).await;
crate::cloud::mirror::spawn_after_commit(mirror_pool, mirror_vault_id);

HttpResponse::Ok().json(UpdateVaultResponse { /* committed values */ })
```

Two ordering facts, both enforced by the control flow above this block:

1. **Strictly after the CAS.** The `Ok(_)` arm of the CAS match has already
   returned `409 VERSION_CONFLICT` (`update_vault.rs:122-139`), so a *rejected*
   write never reaches this code. A mirror can never paper over a conflict —
   asserted by `stale_version_still_conflicts_without_mirroring`
   (`update_vault.rs:322-344`).
2. **Strictly before the response.** The binding state is updated while the
   handler still holds the request, so by the time the client learns
   `version: V+1` the server has already recorded that this version owes a
   backup. There is no window where the client knows about a write the server
   has not yet marked as owing one.

### 6.3 Why it does not block the update request

Two distinct claims — don't conflate them.

**(a) The only awaited part is local and tiny.** `mark_pending`
(`mirror.rs:179-191`) is one indexed
`SELECT … WHERE vault_id = ? AND drive_file_id IS NOT NULL`. For a local-only
vault — the overwhelmingly common case — it returns immediately and writes
nothing (test `mark_pending_is_a_noop_without_a_binding`, `mirror.rs:626-642`;
and `local_only_vault_write_needs_no_binding`, `update_vault.rs:348-366`). For a
bound vault it is one further indexed `UPDATE cloud_binding SET sync_status =
'pending'`. No network, no token lookup, no provider call. It sits on the request
path *only* so the UI's "backing up" state is already true when the client sees
the 200.

**(b) The provider write is a detached task.** `spawn_after_commit`
(`mirror.rs:143-168`) is a synchronous `fn` whose entire async content is
`rt::spawn(async move { … })` (`mirror.rs:151`). `actix_web::rt::spawn` enqueues
the future on the runtime and returns; the future is not part of the request's
future, so the handler can return 200 while the Drive round trip is still in
flight. The response body is fully materialised (`UpdateVaultResponse`), not
streamed, so there is nothing left to wait on.

Therefore response latency for `/update_vault` is `O(CAS)` + `O(one indexed
select)` + `O(one indexed update)` — **no Google latency term at all**. A Google
500, a DNS failure, or a socket that never returns is invisible to the caller.

Test: `vault_write_succeeds_even_when_the_mirror_cannot_run`
(`update_vault.rs:293-318`) seeds a bound vault with **no Google token at all**
and asserts `200`, `version == 4`, and that the new ciphertext is genuinely
stored. The mirror in that test cannot possibly succeed; the write still lands.

### 6.4 Why a provider error cannot fail the update request

There is no error path from the mirror back to the request — by construction,
layer by layer:

| Layer | Why a Drive failure cannot propagate |
|---|---|
| `spawn_after_commit` | returns `()`; a failed `claim` only `log::debug!`s and returns (`mirror.rs:144-150`) |
| the spawned task | `mirror_once` discards the result: `let _ = attempt(...)` (`mirror.rs:212-214`) |
| `attempt()` | every exit path is an `Attempt` enum variant — there is no `?` and no `Err` (`mirror.rs:226-332`) |
| `handle_drive_error` / `set_status` | only write `cloud_binding`; their own DB failures are `log::error!` and dropped (`mirror.rs:398-460`) |
| the response | already built from the committed values; nothing downstream reads the mirror result |

Note the direction of control flow: the mirror never returns a value *to*
`/update_vault`. The only channel by which Drive state reaches the write path is
**inbound** — `GET /cloud/binding` — which is a separate, explicitly polled
endpoint (§6.9).

A provider error also cannot corrupt the vault, because the mirror writes only
`cloud_binding`. There is no path from `sync_status` back into `vault.vault`;
`mark_mirrored` / `set_status` filter on `vault_id` and touch binding columns
only (`mirror.rs:367-460`). The failing case is pinned by
`mirror_after_commit_records_failure_without_touching_the_vault`
(`update_vault.rs:372-408`): after a mirror that cannot authenticate, the vault
is still at `version 4`.

### 6.5 What the mirror actually does — `attempt()` (`mirror.rs:226-332`)

It is **level-triggered**: every pass re-reads current state instead of trusting
the event that woke it. That property is what makes retries, coalescing, and
crash recovery work.

1. Load `cloud_binding`. None → `Unlinked` — this vault is local-only, not an
   error (`mirror.rs:233-237`).
2. No `drive_file_id` → `Unlinked` + `NO_DRIVE_FILE`.
3. Load the **live** `vault` row — not the version that triggered the mirror.
   This re-read is the whole basis of the convergence argument in §6.8.
4. **Watermark short-circuit, before any network call** — not even the token
   lookup: `if binding.mirrored_vault_version == Some(vault_row.version) { return
   UpToDate }` (`mirror.rs:264-266`). This is what makes the coalescing re-check
   free and a "Back up now" on an unchanged vault instant
   (test `mirror_now_reports_up_to_date_without_touching_drive`,
   `mirror.rs:729-742`).
5. `package::build(&vault_row)` — re-serialize the ciphertext the server already
   stores into a `VoultPackage` (`package.rs:101-133`). **No decryption, no key
   derivation, no unwrap.** A vault with no password envelope (legacy
   `crypto_version = 1`) is refused as `Unsupported`: a backup that cannot be
   restored on a new device is a backup in name only (`package.rs:101-110`, test
   `mirror.rs:757-783`).
6. `token_store::get_valid_access_token` — refreshes when within 60 s of expiry
   (`token_store.rs:9-29`). Missing/expired → `auth_required` (a user action,
   recorded, never retried in a loop).
7. `set_status(mirroring)` so Settings can show "Backing up…".
8. Resolve the provider-side CAS baseline (`resolve_baseline`, `mirror.rs:336-361`).
9. `drive::replace_vault(token, file_id, bytes, Some(expected))` — conditional
   write (`drive.rs:298-357`).
10. Success → `mark_mirrored(vault.version, Some(new_rev))`. Failure →
    `handle_drive_error` → exactly one of `auth_required` / `conflict` /
    `unlinked` / `error`, each a status write, never an exception.

### 6.6 The provider-side CAS: the mirror can never clobber a newer provider copy

`replace_vault` re-reads the file's revision immediately before the PATCH and
refuses unless it still equals the revision **we** last observed
(`drive.rs:309-325`). That baseline is `cloud_binding.remote_revision` — only
ever a revision this server itself recorded.

- If Drive reports no revision, `ProviderErrorKind::RemoteRevisionUnavailable` (`drive.rs:92`) is
  treated as *no usable CAS token*, **not** as a token that matches everything:
  `resolve_baseline` returns `REMOTE_REVISION_UNAVAILABLE` and the mirror
  refuses rather than writing blind (`mirror.rs:356-358`; test
  `unknown_revision_is_not_usable_as_a_baseline`, `mirror.rs:565-569`). A
  binding adopted from an import has no recorded revision, so it reads a live
  baseline once and persists it before its first conditional write
  (`mirror.rs:346-354`).
- A refusal records `conflict` and **deliberately does not advance
  `mirrored_vault_version`** (`mirror.rs:409-418`). This is the single most
  important line in the file: advancing the watermark on a refused write would
  tell Settings "Backup up to date" while Drive holds something else. Pinned by
  `conflict_does_not_advance_the_watermark` (`mirror.rs:677-701`).
- Consequence: `conflict` is **sticky**. Neither the automatic mirror nor
  "Back up now" will overwrite — the manual action is "try again", never "force"
  (`mirror.rs:193-198`, `cloud/api.ts:216-232`). Resolution is an explicit user
  act outside this path.
- Provider HTTP statuses are normalised into provider-neutral kinds by
  the provider-local status mapper (`cloud/providers/google_drive/status_mapper.rs`): 401 → `auth_required`,
  404 → `unlinked`, 429 → `error`, 5xx → `error`, 409/412 → `conflict`.

### 6.7 Coalescing, and why no committed write is ever dropped

A burst of vault writes must not cost one Drive round trip each. `IN_FLIGHT`
(`mirror.rs:71`) is a process-global
`Mutex<Option<HashMap<String, bool>>>` mapping `vault_id → "a write landed while
this pass was running"`.

- `claim(vault)` (`mirror.rs:79-92`): no entry → insert `false`, return `true`
  (you own the mirror). Entry exists → set it to `true` (a rerun is owed),
  return `false` (do not spawn).
- `settle(vault)` (`mirror.rs:101-105`): **read the flag and remove the entry
  under a single lock acquisition**.
- The spawned loop (`mirror.rs:157-162`): `mirror_once()` → `if !settle() {
  return }` → otherwise loop, bounded by `MAX_MIRROR_PASSES = 8`
  (`mirror.rs:173`).

The race-freedom argument: a concurrent `claim` either sets the flag *before*
`settle` locks (→ we read `true` and loop), or arrives *after* `settle` removed
the entry (→ it wins the claim and spawns its own task). There is no
interleaving in which a committed write leaves the flag set with nobody
scheduled to service it. Asserted directly by
`a_write_during_a_mirror_is_never_dropped` and
`a_write_after_settling_claims_the_vault_fresh` (`mirror.rs:576-611`).

And the belt-and-braces property from §6.5 step 4: even if the pass bound were
hit, the *next* vault write's `attempt()` re-reads the live version and sees
`mirrored_vault_version != version`, so it re-mirrors. **Coalescing is an
optimisation; convergence does not depend on it.**

### 6.8 The guarantee, stated exactly

**Guaranteed.** For every vault write that passes the CAS:

1. The response does not wait on Drive and cannot be failed by Drive.
2. `cloud_binding` is marked as owing a backup *before* the client learns the
   write succeeded.
3. A mirror pass is scheduled, or is folded into a pass already running, and
   that pass re-reads the committed version and attempts a CAS-gated Drive
   write.
4. The attempt either advances `mirrored_vault_version` (success) or leaves it
   untouched and records *why* it did not.

**Not guaranteed.** That any particular version is uploaded exactly once, or
that a backup exists within any time bound.

- **Process death drops the in-flight task.** A restart mid-mirror loses the task
  and `IN_FLIGHT` resets to empty. Startup and periodic sweeps now rediscover
  stale bindings from `vault.version` vs the watermark and retry without an event
  log.
- **A stalled socket is bounded.** Provider calls use one shared reqwest client
  with a 10-second connect timeout and 30-second request timeout. The vault write
  path remains detached and unaffected.

So the guarantee is **convergence plus visibility**, not exactly-once delivery.
That is the right trade for a copy whose only job is to exist if the server
dies. The watermark is the honest signal: `mirrored_vault_version` vs live
`vault_version` yields `versions_behind` (`cloud_endpoints.rs:418-449`) — the
number of committed writes the DR copy is missing. Everything the UI says is
derived from that, so a stalled or failed mirror is **visible**, never silent.

### 6.9 What the client sees, and how it learns

- `GET /api/cloud/binding` returns the real state: `sync_status`,
  `vault_version`, `mirrored_vault_version`, `versions_behind`,
  `last_mirrored_at`, `last_mirror_error` (`cloud_endpoints.rs:398-450`).
- Because the mirror is detached, the client must poll for it:
  `useGoogleBinding` uses `staleTime: 5_000` + `refetchOnWindowFocus` with a
  comment stating exactly why (`cloud/queries.ts:52-64`).
- `describeBackup` (`cloud/backup-status.ts:37-104`) maps state → sentence.
  `behind > 0 || pending || mirroring` is the yellow "Backup is N changes behind"
  / "Backing up…" branch (`:81-93`), and `conflict` / `auth_required` / `error`
  each render with an explicit *"Your vault on this device is unaffected."*
- `POST /api/cloud/vaults/mirror` ("Back up now") awaits `mirror_now` and
  returns the discriminated `MirrorOutcome` (`cloud_endpoints.rs:573-614`,
  `mirror.rs:107-136`, `MirrorResult` in `cloud/api.ts:206-214`), so the user
  learns what actually happened instead of a permanent "Encrypted sync enabled"
  label. The button is disabled when the backup is already current
  (`settings/index.tsx:221`).
- Enrollment records the truth rather than assuming it:
  `POST /cloud/vaults/create` creates/adopts the file, leaves the watermark
  unset, then awaits `mirror_now` so an adopted stale file is repaired before it
  can be considered current (`cloud_endpoints.rs:709-779`). Provider switching
  through `POST /cloud/binding?provider=...` uses the same pattern; importing an
  existing backup can record its known imported version directly.

### 6.10 The zero-knowledge boundary of the mirror

`package::build` copies only fields the server already stores: `vault.vault`,
`vault.vaultiv`, `salt`, `iterations`, `crypto_version`, `vault_key_wrap`,
`vault_key_wrap_iv` (`package.rs:113-130`). Nothing is decrypted, unwrapped, or
derived, and `vault_verifier` is deliberately **not** in the package. The JSON
shape is pinned by tests against the client's `VoultPackage` so a rename would
break restore-from-Drive on another device (`package.rs:156-173`).

Logs carry only truncated vault ids and provider revisions (`short_id`,
`mirror.rs:487-490`) and short provider codes (`error.rs:43-57`) — never tokens,
provider response bodies, ciphertext, or key material. The OAuth token is only
ever read from `cloud_token` and used as a bearer header.

### 6.11 Remaining gaps in the provider path

1. **`IN_FLIGHT` is process-local.** Correct for the single-process localhost
   server this ships as; a multi-process deployment would need a DB-level claim
   or a job queue.
2. **`mark_adopted` and `observe_remote_revision` are uncalled**
   (`mirror.rs:469-505`) — kept with tests, but adoption currently happens via
   the `/cloud/binding` upsert instead.
3. **No fake-provider transport test.** The mirror's state logic is covered
   (watermark, conflict, unlinked, coalescing, unsupported) and `/update_vault`'s
   commit-with-provider-unavailable is covered, but conditional writes against
   real providers are not (42 server tests pass as of this
   writing; see `SECURITY_AND_FEATURE_ROADMAP.md:51`).
4. **`cloud_token` stores provider credentials in plaintext SQLite**, and
   mirroring puts them on the hot path of every vault write
   (`SECURITY_AND_FEATURE_ROADMAP.md:66`).

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
8. **A Drive failure is never a vault-write failure.** `/update_vault` returns
   as soon as the CAS commits; the mirror is detached, its result is discarded,
   and its errors land in `cloud_binding` only (§6.4).
9. **Drive is a copy, never the authority.** No read path, no merge decision,
   and no session/lock decision may consult Drive. The client pulls only
   `/get_vault` (§6.1).
10. **Never claim the backup is current without a successful conditional
    write.** `mirrored_vault_version` advances only in `mark_mirrored`; a
    refusal (`conflict`, `auth_required`, `unlinked`, `error`) must leave it
    untouched, or `versions_behind` starts lying (§6.6).
11. **Never mirror before the CAS resolves.** The mirror is only reachable on
    the `rows_affected > 0` arm, so it can never resurrect a rejected write
    (§6.2).

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
| `remote.ts` | **Removed.** `getVaultRemote` / `GoogleRemote` / `isGoogleRemoteError` had no importers. The model settled on: **the server is the write authority, the provider is the disaster-recovery copy.** The client pulls only `/get_vault`; the server re-writes the provider copy after each CAS via `apps/server/src/cloud/mirror.rs` — see §6. |
| `type.ts` | Re-exports op schemas from `@voult/vault-core` |

## Server-side files referenced by §6

None of these are in `apps/client/src/lib/sync/`, but the Drive half of vault
sync is entirely server-side, so the path from a committed CAS to a provider write
lives here:

| File | Role |
|---|---|
| `apps/server/src/endpoints/update_vault.rs` | The CAS, then `mark_pending` + `spawn_after_commit` (§6.2) |
| `apps/server/src/cloud/mirror.rs` | `spawn_after_commit`, `attempt`, `claim`/`settle`, watermark and status writers (§6.3–6.8) |
| `apps/server/src/cloud/package.rs` | Re-serializes stored ciphertext into a `VoultPackage`; never decrypts (§6.5, §6.10) |
| `apps/server/src/cloud/drive.rs` | Drive HTTP: `replace_vault` with `if_match_revision`, `file_revision`, `UNKNOWN_REVISION` (§6.6) |
| `apps/server/src/cloud/token_store.rs` | Access token, auto-refresh inside 60 s of expiry (§6.5) |
| `apps/server/src/cloud/error.rs` | Provider-neutral `ProviderErrorKind` and HTTP status mapping (§6.6) |
| `apps/server/src/entity/cloud_binding.rs` | `mirrored_vault_version`, `last_mirrored_at`, `last_mirror_error`, `sync_status` |
| `apps/server/migration/src/m20261011_000004_cloud_binding_mirror_state.rs` | Adds those four columns, all nullable |
| `apps/server/src/endpoints/cloud_endpoints.rs` | `/cloud/binding` (`versions_behind`), `/cloud/vaults/mirror`, enrollment/import bindings (§6.9) |
| `apps/client/src/lib/cloud/backup-status.ts` | Binding state → user-facing backup status (§6.9) |
| `apps/client/src/lib/cloud/enableSync.ts` | The one-time enrollment that creates the binding |
