# Multi-device conflict resolution for the vault

Design document. Scope: approach + edge-case handling only — not an implementation plan.

## 1. The constraint that drives everything

End-to-end encryption means the server can never participate in conflict resolution. It cannot see items, fields, or op semantics — only ciphertext. So:

- All merging happens **client-side**, on whichever device is syncing.
- The server's only job is a **version-based CAS** (compare-and-swap) over the whole encrypted blob: "accept this push iff it's based on the version I currently have."

The second consequence is subtle and very useful: **the version CAS already serializes merges.** If devices A and B are both at version 5 with local edits and both sync, only one push wins (→ version 6). The loser gets a `409`, re-fetches the winner's snapshot, and merges its own edits onto **that**. So no two devices ever independently merge the same base and fight. Every merge in the system is a single-writer deterministic function: `merge(serverSnapshot, myPendingIntents)`. We do not need a full distributed merge protocol.

## 2. The two cases — and the collapse that removes the special-casing

| Case | Condition | Correct action |
|---|---|---|
| 1 | server ahead, **no** local intents | Adopt the server snapshot locally (update store + local version). **No push.** |
| 2 | server ahead, **pending** intents | Conflict: replay local intents onto the newer server snapshot, encrypt, push. |

Both are "reconcile my local state to the latest server snapshot"; the only difference is whether there's anything to replay. So the fix is to **delete the version-equality special-casing entirely** and make sync always:

```
fetch server snapshot (S_server, V_server)

if V_local == V_server and no pending intents        → done
if V_local != V_server and no pending intents        → adopt S_server locally; done        (case 1)
if pending intents:
  M = replay(pendingIntents, S_server)                                                      (case 2 and every conflict)
  push M with base version V_server
  on 409 → re-fetch, re-merge, re-push (bounded)
  on success → update V_local, mark intents synced
```

The current `if ((localVersion ?? 0) !== serverVersion) { abort }` in `sync/index.ts` is precisely what blocks conflict handling — under the new model the server version is the source of truth and divergence is *normal*, not an error.

## 3. Recommendation: intent-replay (event sourcing), not CRDT

The Figma multiplayer design (stable object ids, per-node LWW, op log, server serialization) is a good reference. Two ideas transfer directly — but a full CRDT is the wrong tool for a password vault, and there's a cheaper path that uses infrastructure we already have.

**What we borrow from Figma:** stable object IDs, an op log as the source of truth, deterministic merge, and per-field last-write-wins. The local `intent` table is already that op log.

**Why not a CRDT (Automerge/Yjs, or a custom one like Figma's):**

| | Intent-replay (recommended) | CRDT (Automerge/Yjs) |
|---|---|---|
| Fits existing intent table | Yes — it *is* the op log | Rewrites the data model |
| New dependency | None | Automerge/Yjs + serialization changes |
| Conflict freedom | Deterministic per-op rules; LWW per field | Commutative by construction |
| Storage | Server stays an encrypted blob | Server must store CRDT state/changelog (still encryptable, but the merge needs the op history) |
| Cost profile | Right-sized for rare, small conflicts | Pays full price for a problem that's rare here |

The vault has tiny, low-write-frequency, flat records (`site, username, password`). CRDTs shine on rich, rapidly-edited, nested documents. For a vault, the realistic conflict is "two devices touched the same entry" — which a small policy table handles deterministically, for free, with no data loss beyond a documented last-sync-wins field.

**Honest caveat:** CRDT is the right call if any of these become hard requirements — *no* field edit is ever lost, real-time collaborative editing, or the vault evolves into nested/complex documents. That's the future migration path; the design below keeps the op log in a shape that could seed an Automerge doc later.

## 4. Foundations needed before merging can work

Conflict resolution is only possible if these exist. Today they don't.

**4a. Stable item IDs.** Items are `{site, username, password}` with no id — identity is the natural key `(site, username)`. That's broken for merging: renaming a username turns an update into delete+create, and two devices adding "the same" account are indistinguishable from unrelated entries. Fix: every `VaultItem` gets a **UUID `id`**, and all ops reference it.

**4b. Idempotent operations.** Because sync may retry an intent (lost response, 409), replaying the *same* op twice must be a no-op. That's what makes retries and lost-response recovery safe.

**4c. Update/delete intents with changed-fields payloads.** Today only `create` is supported, and it carries the whole item. To merge without losing data, `update` should carry `{ itemId, fields: { site?, username?, password? } }` (only what changed) so two devices editing *different* fields of the same entry both survive. `delete` carries just `itemId`.

**4d. A real, persisted `device_id`.** It's hardcoded `"test_device_id"` in `handleCreate`. Device identity matters for deterministic tiebreaks and for debugging which device wrote what. Persist it (`upsertDeviceId` already exists but is never called).

**4e. `schemaVersion` inside the vault payload.** So future vault-format changes (adding ids, tombstones) are migratable instead of unreadable.

**4f. Gate `vault_version` writes to sync.** Today `useGetVault`'s effect writes the fetched server version into `client_state.vault_version`. If a background fetch inflates the local version, divergence detection is unreliable and you can get pointless pushes. Let sync be the sole writer of the local base version.

## 5. The merge policy

`merge(pendingIntents, serverSnapshot)` — replay intents in **`(created_at, id)` order** (id tiebreak makes it deterministic even for same-millisecond writes on one device), applying:

| Intent op | State on server snapshot | Result |
|---|---|---|
| `create {id, site, username, password}` | id already present | no-op (idempotent replay) |
| `create {id, …}` | natural key matches an existing item | **keep both** (duplicates) — no data loss; a future "find duplicates" UI can offer merging |
| `create {id, …}` | nothing | insert |
| `update {id, fields}` | item present | merge fields: `item = {…serverItem, …fields}` (per-field LWW, local wins) |
| `update {id, fields}` | item absent (deleted by another device) | **drop + log** — deletes are sticky; an update can't resurrect a deliberately deleted entry |
| `delete {id}` | item present | remove |
| `delete {id}` | item absent | no-op (idempotent) |

Three deliberate semantics, stated plainly:

- **Local edits win on items that still exist.** Because merges are single-writer-per-version (CAS), "local wins" equals "**the device that syncs last wins per field**." This is the standard, understandable v1 semantic.
- **Remote deletes win on items that were removed.** Absence means another device deliberately deleted it; we don't resurrect via a stale update. If the user genuinely wants the entry back, they re-create it (a fresh id), which inserts normally.
- **Natural-key create conflicts keep both.** Choosing "newest" would silently discard data and orphan subsequent intents that reference the dropped id; keeping both loses nothing.

No rule relies on wall-clock across devices. `created_at` only orders writes *within a device* (safe); cross-device conflicts are resolved by the single-writer merge, not by timestamps. This sidesteps clock-skew entirely.

## 6. Edge cases

| # | Case | Handling |
|---|---|---|
| 1 | Concurrent push from the same version (true simultaneous sync) | CAS makes one win; loser gets `409`. Must NOT drop intents — re-fetch, re-merge, re-push, bounded (e.g., 3 attempts), then leave intents pending for the next trigger |
| 2 | Response lost after a successful push | Client never saw the ack, so intents stay pending and it retries. Idempotency (5) makes the replay harmless (server already has the change; push becomes an empty version bump) |
| 3 | `V_local > V_server` (client ahead — server DB restored / rollback) | Reconcile to the server snapshot; if local intents exist, merge them on. Server version is truth; never abort on direction of inequality |
| 4 | Same version but divergent content (server-side tampering or bug) | Optional hardening: compare a hash of local vs fetched vault when versions match and no intents pending; adopt server on mismatch |
| 5 | Two devices create the same account (natural-key conflict) | Covered by keep-both |
| 6 | Update of an item another device deleted | Covered by drop (delete-wins, no resurrection) |
| 7 | Delete of an already-deleted / never-existed item | No-op — makes replay safe |
| 8 | Long offline period, many accumulated intents | Replay handles arbitrary divergence — every pending intent is preserved until pushed, replayed in deterministic order. No cap on skew |
| 9 | Intent with an unknown op, or that fails to decrypt/parse mid-replay | **Quarantine it** (set the `error` column; it already exists) and continue with the rest — instead of the current behavior of aborting the entire sync. One bad intent should never block the vault |
| 10 | `useGetVault` overwriting the base version | Fixed by 4f |
| 11 | Server CAS not atomic | `update_vault` is read-then-write (`find` then `update`) — a TOCTOU window where two concurrent `409`-free pushes both pass the check. Harden: `UPDATE vault SET version = version + 1, vault = ?, vaultiv = ? WHERE id = ? AND version = ?` and require `rows_affected == 1` |
| 12 | Legacy data without ids | Needs a one-time migration/backfill when ids are introduced (4a) — either assign ids on first sync or rewrite the stored vault once |
| 13 | Clock skew | Non-issue by construction (no cross-device timestamp ordering), but worth stating so nobody "fixes" it later with a timestamp comparison |
| 14 | Empty-push churn from lost-response retries | Optional: hash-compare the merged vault against the fetched snapshot and skip the push if identical |

## 7. Deferred (explicitly out of scope for v1)

- **Tombstones** — the principled fix for delete-vs-update ordering beyond "deletes are sticky." Only needed if you later want "recently-deleted items are recoverable" or fine-grained delete-undo.
- **Conflict-surfacing UI** — a "duplicates found" view, or flagging entries that were merged with field-level conflicts for user review.
- **Real CRDT (Automerge/Yjs)** — the migration path if no-loss-per-field or real-time collaboration becomes a requirement.
- **Server-side per-item storage** — if the vault ever gets too big to push whole, you'd store per-item encrypted blobs and the version model becomes a Merkle/log structure. Not needed at vault scale.

## 8. Relationship to the SyncScheduler

Nothing structural changes — it stays a blackbox serializer. The only change is *inside* `sync()`: it becomes a bounded reconcile-retry loop instead of a single-shot-with-aborts, and the merge policy (5) replaces the version-mismatch abort. The scheduler's coalescing (one run + one follow-up) already composes correctly with the retry loop.
