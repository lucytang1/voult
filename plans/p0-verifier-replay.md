# P0 — Remove the reusable verifier as a directly replayable login credential

**Status:** implemented 2026-10-29 (see §11 for the verification record)
**Item:** [`SECURITY_AND_FEATURE_ROADMAP.md`](../SECURITY_AND_FEATURE_ROADMAP.md) §"Security issues → Open issues — fix before public release", P0 "Remove the reusable verifier as a directly replayable login credential" (line 57)
**Decision (confirmed with the owner):** store a **salted HMAC of the verifier**, not a PAKE. OPAQUE is recorded as the end-state with explicit re-open triggers (§4.2). The wire contract does not change; `apps/client` and `apps/extension` get a **zero-line** diff.

---

## 1. What the code does today

`POST /api/auth` accepts `{ vault_id, vault_verifier }` (`apps/server/src/endpoints/auth.rs:14-21`), loads the vault row, and compares the submitted string to the stored column with ordinary `!=`:

```rust
// apps/server/src/endpoints/auth.rs:99
if vault.vault_verifier != request.vault_verifier {
```

The stored value is not a hash of anything — it *is* the credential. The client computes it as `HMAC-SHA256(authKey, "auth-v1||static")` (`packages/vault-core/src/crypto.ts:185-194`), where `authKey = HKDF-SHA256(PBKDF2-SHA256(password, salt, iterations), info="auth")` (`crypto.ts:23`, `crypto.ts:324-334`). It is deterministic: the same password + salt + iterations always produce the same 32 bytes, which the web app sends on every re-auth (`apps/client/src/lib/auth/flows.ts:182-184`), the extension sends on every unlock (`apps/extension/src/background/vault.ts:513-515`), and signup/import/recovery compute identically (`apps/client/src/lib/auth/flows/signup.ts:87`, `apps/client/src/lib/vault/import.ts:166`, `apps/client/src/lib/auth/flows/recover.ts:237`).

So the `vault` row holds a **bearer token that is also a password verifier**. Anyone who can read one row — a copied SQLite file (`~/Library/Application Support/Voult/voult.db`), a Time Machine/backup snapshot, a support bundle, a future read-only DB compromise, a mis-scoped local process — can `POST /api/auth` with that string and receive an HttpOnly `voult_session` cookie, with no password and no cracking. The session is scoped to that vault only (`apps/server/src/session_auth.rs:6`, `:32-38`), so the gain is not plaintext — the vault body is still AES-GCM ciphertext under a key the attacker does not have. The gain is **every session-scoped capability**: read the ciphertext and its envelopes, overwrite the vault through `/update_vault` (CAS is satisfiable from the same dump), bump `lock_epoch`, touch cloud bindings, mint pairing codes. Read-only DB access becomes an authenticated write identity.

Two secondary facts complete the picture:

- The verifier is **offline-checkable without the DB**. `GET /api/get_crypto_params?vault_id=…` returns `salt` and `iterations` unauthenticated (`apps/server/src/endpoints/get_crypto_params.rs:23-46`), and the verifier is a pure function of those plus the password. Anyone who ever obtains a verifier — a logged request body, a proxy, a screenshot of a devtools panel — can test password guesses against it offline, forever.
- The comparison is also not constant-time, but that is the smaller half. With a 256-bit value, a prefix-timing attack over HTTP is not the realistic path; the replay is.

**"Fixed" means:** the row contains no value that can be presented to `/auth`. The client keeps sending the same verifier; the server stores `HMAC-SHA256(fresh per-write salt, presented)` and compares in constant time. A dumped row then yields a hash whose preimage is the verifier, and the verifier is only recoverable by guessing the password.

### 1.1 Does hashing actually stop replay, or just add a cracking step?

It **stops replay, and adds no cracking step at all.** Precisely:

- The stored value is `H = HMAC(salt, V)`. To authenticate, an attacker must present `V`, the preimage. Sending `H` fails, because the server hashes what it receives. This is *not* pass-the-hash: the thing on the wire is the preimage, the thing at rest is the digest, and the server hashes on arrival. (Pass-the-hash would be "store `H`, have the client send `H`, compare `H == H`" — explicitly not what this design does; §6 makes that a review invariant.)
- `V` is not 256 bits of unguessable entropy in practice: it is `HMAC(authKey, label)` where `authKey` is derived from a *human password* with PBKDF2-SHA256 at 60,000 iterations (`crypto.ts:12`). So a DB-dump attacker recovers `V` by guessing the password.
- That guess costs exactly what guessing the password **already** costs, because the same row contains `vault_key_wrap`: the AES-GCM envelope of `vaultKeyRaw` under `HKDF(root, "vault-wrap-v2")`, derived from the **same PBKDF2 root with the same salt and iterations** (`crypto.ts:310-320` vs `:324-334`). One PBKDF2 evaluation per candidate password tests both targets, and the envelope is the better target because success yields the vault key rather than a session.

Therefore the honest delta is: **the zero-work path disappears; the worst-case outcome of a DB dump does not change.** After the fix, a DB dump still means offline password cracking against `vault_key_wrap` — that is the separate KDF P0 (roadmap line 56), not this one. What this item buys is that read-only DB access no longer grants a live session, write access, or an authenticated identity. That is exactly the harm the roadmap item names, and it is fully closed.

Corollary, and the reason the PAKE verdict below is not "PAKE is worthless": **no symmetric challenge–response can do better against this threat.** A challenge–response where the server verifies `MAC(secret, challenge)` requires the server to hold `secret`; a DB dump then hands the attacker the MAC key, and they can answer any challenge. A server that stores `H(secret)` cannot verify such a MAC. So "hash at rest" and "non-replayable proof" are mutually exclusive for a symmetric verifier — that gap is precisely what an aPAKE fills, and it is the only reason to pay for one.

---

## 2. Research: is the roadmap claim still accurate?

**Yes. The core claim is accurate; two details in it are imprecise.**

Verified still true:

- `auth.rs:99` is ordinary `!=` string comparison of the stored column, unchanged. No hashing, no constant-time compare anywhere on this path.
- The column is `vault_verifier TEXT NOT NULL` (`apps/server/migration/src/m20260901_000001_vault_centric_init.rs:19`), plaintext, no salt, no hash (`apps/server/src/entity/vault.rs:17`).
- `/auth` is registered unauthenticated inside the `/api` scope (`apps/server/src/main.rs:319-320`).
- Nothing else reads the verifier: `get_vault` returns only ciphertext/envelope fields (`apps/server/src/endpoints/get_vault.rs:15-23`), `list_vaults` returns id/version/crypto_version/created_at (`apps/server/src/endpoints/vaults.rs:193-207`), and the cloud package deliberately omits it (`apps/server/src/cloud/package.rs:6-13`; `apps/client/src/lib/sync/README.md:519`). So the column is *only* an auth credential — which is good news: there is nothing else to migrate.

Corrections to the record:

1. **"Compares with ordinary string equality" is not the vulnerability** — it is a symptom. The vulnerability is that the column is a password-equivalent bearer token. Fixing only the comparison (constant-time) would leave the replay fully intact. The plan must not be read as "swap `!=` for `ct_eq`".
2. **The exposure is wider than "anyone who obtains the DB verifier."** `get_crypto_params` is unauthenticated and returns the KDF inputs, so a verifier obtained *without* the DB (a logged body, a proxy, a devtools capture) is also offline-checkable forever. Hashing at rest does not revoke a verifier that already leaked; only a credential rotation does (recovery rewrap or the P1 password-change flow).
3. **"Partially addressed" does not apply here** — unlike the neighbouring rate-limit and bounds items, nothing on this path has been hardened. The only related work is the recovery path, which already uses the pattern this item should converge on: an HMAC proof bound to a fresh server challenge (`apps/server/src/endpoints/recovery.rs:188-198`, `:333-345`) and uniform `401 AUTH_FAILED`.

**Overlaps, and why they are not fixed here:**

| Overlap | Seam | Why out of scope |
|---|---|---|
| P0 rate limiting (`auth.rs`, roadmap line 58) | `/auth` has no application limit; hashing does not change online guessing at all (the attacker guesses passwords, not verifiers). | Independent control. This plan must not quietly become a rate-limiter. |
| P0 request/protocol bounds (roadmap line 61) | `/auth` and `/register` accept any non-empty string; this plan adds only the length guard the HMAC needs. | Full canonical-base64/32-byte validation stays with that item. §4.5 pins a constant so the guard is not re-litigated. |
| P1 account enumeration (roadmap line 70) | `/auth` already returns one generic `AUTH_FAILED` for unknown-vault and bad-verifier; the DB lookup still differs in timing. | Unchanged behaviour, must stay unchanged. |
| P1 password-change protocol (roadmap line 71) | `update_vault_password.rs` writes a verifier without a rewrap. | This plan only stops it writing *plaintext*; its broken semantics stay with that item (§5, do-not-fix note). |
| **Adjacent finding, not on the roadmap** — `recovery_verifier` is a plaintext HMAC key (`entity/vault.rs:39`), so a DB-dump attacker can forge a valid proof and call the unauthenticated `/recovery/rewrap` with a self-chosen envelope. | §9.1 | Separate mechanism, separate fix (needs asymmetric proof-of-possession). Documented so nobody believes this item closed every DB-dump path. |

---

## 3. Chosen design

### 3.1 Storage

Two new columns on `vault`, replacing `vault_verifier`:

| Column | Type | Contents |
|---|---|---|
| `verifier_salt` | `TEXT NOT NULL DEFAULT ''` | 16 random bytes (CSPRNG), standard base64. Public, non-sensitive. |
| `verifier_hash` | `TEXT NOT NULL DEFAULT ''` | `HMAC-SHA256(key = salt_bytes, msg = "voult-verifier-v1|" + presented_utf8)`, standard base64 (32 bytes). Treat as sensitive: it is the at-rest form of the credential. Never log. |

`vault_verifier` is **dropped**, not reused. A column named `vault_verifier` holding a hash is the exact confusion this item exists to end.

Why HMAC and not `SHA256(salt||verifier)`: `hmac` is already a direct dependency (`apps/server/Cargo.toml`, used by `recovery.rs`), and `Mac::verify_slice` gives a constant-time comparison without a hand-rolled loop. With a public key the two constructions are equivalent in strength; HMAC is chosen for the constant-time verify and to avoid a second hand-rolled comparison on a credential path.

Why a fresh random salt per credential write rather than the existing PBKDF2 `salt`: honesty first — the marginal value is small, because the verifier is already unique per vault (the PBKDF2 salt is per-vault) and 256 bits wide, so there are no rainbow tables and no cross-row equality to break. It is included because it is the standard shape for a stored password verifier, it costs one 16-byte column, and it guarantees the stored value is never equal to a hash of the same verifier produced elsewhere. It is *not* a pepper (see §4.6) and it is not a secret.

### 3.2 Wire contract — unchanged

`POST /api/auth` keeps `{ "vault_id": string, "vault_verifier": string }` and `POST /api/register` keeps `vault_verifier`. The field name stays because the value genuinely is still the verifier; what changed is that the server no longer stores it. Renaming to `credential_proof` was considered (§4.4) and rejected.

Nothing else moves: `/register`, `/vaults`, `/recovery/rewrap`, `/vault/password` all keep their payload shapes, and the client keeps computing the verifier from the master password exactly as today. **`apps/client` and `apps/extension` require no code change.** That is the single biggest risk reduction in this plan: the zero-knowledge boundary, Rule R1, the device-envelope path and the recovery flow cannot regress because none of them is touched.

### 3.3 Server module: `apps/server/src/credentials.rs`

New crate-root module (sibling of `session_auth.rs`), declared in `main.rs` next to `mod session_auth;` (`main.rs:8`).

```rust
//! Password-credential at rest.
//!
//! The client proves knowledge of `vault_verifier`; the server stores only a
//! keyed hash of it. The presented value is the HMAC preimage and is never
//! persisted, so a copied database row cannot be replayed against POST /auth.
//! It is still a bearer credential in transit — see plans/p0-verifier-replay.md.

/// 16-byte random salt, base64. Public; stored beside the hash.
pub const VERIFIER_SALT_LEN: usize = 16;
/// HMAC-SHA256 output, base64.
pub const VERIFIER_HASH_LEN: usize = 32;
/// The real verifier is 44 base64 chars (32 bytes). This cap only stops an
/// unbounded string reaching the HMAC; canonical base64 validation belongs to
/// the request-bounds P0.
pub const MAX_VERIFIER_LEN: usize = 256;
/// Domain separation. Changing this invalidates every stored credential, so it
/// is fixed for the lifetime of the schema.
const VERIFIER_HASH_LABEL: &str = "voult-verifier-v1|";

pub struct StoredCredential {
    pub salt_b64: String,
    pub hash_b64: String,
}

/// Mints a fresh salt and the matching hash. `None` when the presented value is
/// empty or oversized (caller answers INVALID_INPUT).
pub fn new_credential(presented: &str) -> Option<StoredCredential>;

/// True only when `presented` hashes to the stored value under the stored salt.
/// Constant-time. Returns false — never an error — for empty or malformed
/// columns, so a row written before this change fails closed as a plain
/// AUTH_FAILED rather than a 500.
pub fn accepts(salt_b64: &str, hash_b64: &str, presented: &str) -> bool;

/// Length/emptiness guard shared by /auth and the writers.
pub fn acceptable(presented: &str) -> bool;
```

Implementation notes for whoever writes it:

- Hash the **UTF-8 bytes of the presented string**, not its base64-decoded bytes. The credential is "the exact string the client sends", which is what it always was; this avoids re-litigating base64 canonicalisation (a different uniform encoding would otherwise become a second accepted credential) and keeps every existing test fixture valid. See §4.5.
- `accepts` decodes salt to exactly `VERIFIER_SALT_LEN` and hash to exactly `VERIFIER_HASH_LEN`; any failure returns `false`. `Mac::verify_slice` on the recomputed HMAC does the comparison.
- No `Debug`/`Display` that prints the hash. Do not log either value, ever (consistent with `AGENTS.md:72`, which already forbids logging `vault_verifier`).
- Unit tests pin a known-answer vector for `HMAC-SHA256(key = 00×16, msg = "voult-verifier-v1|abc")`, generated once with `openssl dgst -sha256 -mac HMAC -macopt hexkey:00000000000000000000000000000000` and hard-coded. A label change must fail a test, not silently invalidate every vault.

### 3.4 Readers and writers (all inside the existing transactions)

| Site | Change |
|---|---|
| `endpoints/auth.rs:99` | `if !credentials::accepts(&vault.verifier_salt, &vault.verifier_hash, &request.vault_verifier)` → same uniform `401 AUTH_FAILED`. Add `credentials::acceptable` to the pre-flight check at `:55-61`. |
| `endpoints/register.rs:148` | Hash before the transaction opens (alongside the existing pre-flight validation at `:84-98`), store `verifier_salt`/`verifier_hash`, drop the plaintext from the `ActiveModel`. |
| `endpoints/vaults.rs:134` | Same helper. `vault_verifier` becomes a required `String` (was `Option<String>` + `unwrap_or_default()`, which could create a row with an empty, unloginable credential). The endpoint is unreferenced by the client, so this has no client impact. |
| `endpoints/recovery.rs:849-866` | Inside the **same** CAS `update_many` that bumps `credential_version`, replace `VaultVerifier` with a fresh `VerifierSalt`/`VerifierHash` pair derived from `request.new_vault_verifier` (already validated as 32 bytes at `:768-773`). No new statement, no window where the row has a half-written credential. |
| `endpoints/update_vault_password.rs:55` | Route through the helper so it can never write plaintext. Its missing rewrap/reauth semantics stay with the P1 item; add a comment pointing at it. |
| Test fixtures | `vault_verifier: Set("dmVyaWZpZXI=")` and JSON fixtures in `update_vault.rs:259`, `recovery.rs:1232/1334/2047`, `cloud_endpoints.rs:1664/1701`, `cloud/package.rs:201/298`, `cloud/mirror.rs:1107/1368`, `register.rs:315` move to the two new fields. Mechanical; no behaviour under test changes. |

Ownership detail at `register.rs`: `request.vault_verifier` is currently moved into the `ActiveModel`. Compute the credential first, then move/drop the plaintext — the compiler enforces that the old field no longer exists.

### 3.5 Migration

New `apps/server/migration/src/m20261028_000008_vault_verifier_hash.rs`, registered in `migration/src/lib.rs` after `m20261027_000007`:

```rust
// up
alter table vault add column verifier_salt TEXT NOT NULL DEFAULT ''
alter table vault add column verifier_hash TEXT NOT NULL DEFAULT ''
alter table vault drop column vault_verifier

// down
alter table vault add column vault_verifier TEXT NOT NULL DEFAULT ''
alter table vault drop column verifier_salt
alter table vault drop column verifier_hash
```

- SQLite ≥ 3.35 is required for `DROP COLUMN`; the build pins `libsqlite3-sys 0.30.1` (`apps/server/Cargo.lock`), i.e. bundled SQLite 3.46. No new dependency, no table rebuild.
- `DEFAULT ''` is what makes the migration legal on a non-empty table. It is also the **fail-closed sentinel**: `accepts(…, "", …)` is false, so a pre-existing row answers `401 AUTH_FAILED` rather than crashing. `down()` is honest about being lossy — the plaintext cannot be reconstructed.
- **No backfill.** A row's plaintext verifier *could* be turned into `HMAC(salt, old_value)` at migration time and would keep working, but that would put a second credential implementation inside the migration crate, only for pre-release dev data, and it would be untestable against the runtime path it has to match. `migration/src/lib.rs:5-8` already establishes "breaking schema changes mean delete the dev DB" as this repo's convention. A migrated row is dead; recreate the vault. This is called out in the acceptance criteria so it is not a surprise.
- Migration mechanism note: this adds a new migration file because that is how this repo evolves schema (`Migrator::up` runs on startup, `main.rs:222`). It is **not** a compatibility layer: there is no dual-read, no legacy branch, no version field.

### 3.6 Startup audit (M3)

After `Migrator::up` in `main.rs:222`, count rows that cannot authenticate and emit **one** warning with a count and no identifiers (the log-sanitisation P0 forbids vault ids in logs):

```rust
// Rows below this migration have no credential hash and cannot log in.
// One line, count only — never ids, never values.
let unusable = vault::Entity::find()
    .filter(vault::Column::VerifierHash.eq(""))
    .count(db_data.get_ref())
    .await
    .unwrap_or(0);
if unusable > 0 { SERVER_LOG.warn(…count…, logger::Metadata::new()); }
```

Without this, a migrated install looks like "wrong password" forever and nobody knows why. With it, the first start says exactly how many vaults need recreating.

---

## 4. Alternatives considered (with verdicts, so they are not re-litigated)

### 4.1 Constant-time comparison only — **REJECTED**
Swapping `!=` for `subtle::ConstantTimeEq` closes a hypothetical prefix-timing channel and leaves the actual vulnerability untouched: the column is still presentable. Worse, it would let the roadmap item be marked done. Not sufficient, not even the main part.

### 4.2 OPAQUE / RFC 9807 aPAKE — **REJECTED for this item; target end-state**
The genuinely strong answer, and the roadmap's stated preference. Costed honestly:

- **Dependency spread.** `opaque-ke` exists for Rust; there is no first-party TypeScript implementation. The web client needs a WASM build wired through Expo's web export, and the MV3 extension needs the same module in its service worker with `'wasm-unsafe-eval'` added to `content_security_policy.extension_pages`. That is a new crypto dependency on three build pipelines plus a browser-support floor, replacing `crypto.subtle` calls that are currently auditable in one file.
- **Protocol shape.** Login becomes 3 messages (KE1/KE2/KE3) instead of one `POST /auth`, and registration becomes a 2-message enrolment instead of one field in `/register`. The client needs the server's OPAQUE record pre-auth, so `get_crypto_params` grows a payload. The aPAKE also yields an export key and session key we would discard, because sessions are cookie-based (`session_auth.rs`).
- **Recovery is the blocker.** OPAQUE registration is `RegistrationRequest → RegistrationResponse → RegistrationUpload`: the client cannot produce the final record without a server round-trip. `/recovery/rewrap` is today a **single atomic CAS write** that rotates the password credential and establishes the session (`recovery.rs:734-900`); it cannot also install an OPAQUE record. Making it two steps introduces a row state with a password envelope but no usable auth record — precisely the "a vault must never exist in a state where its credential is broken" invariant this codebase spends effort protecting (`AGENTS.md` recovery section; `register.rs:84-98`). The alternative (keep the verifier alongside OPAQUE during a transition) is the worst of both.
- **Device unlock: unaffected.** `unlockWithDevice` never presents a password; it reads the cookie (`GET /session`) and unwraps the vault key with the local device key (`apps/client/src/lib/auth/flows.ts:53-86`). A PAKE changes nothing here — worth stating because it is often assumed otherwise. **Rule R1 is also untouched**: OPAQUE would replace the password *auth* credential, not the recovery envelope, which wraps `vaultKeyRaw` directly.
- **Marginal benefit, stated plainly.** Against a DB dump, OPAQUE buys **nothing beyond hashing**, because the same row's `vault_key_wrap` is already a password-derived offline-cracking target. Its real benefit is that no reusable credential crosses the wire. On a loopback/HTTPS single-tenant deployment, an attacker who can read the request body is on the client or has broken TLS — and in the first case the master password is in the same process. The benefit is real but narrow.

**Re-open triggers (recorded so this is a decision, not an omission):** a hosted/multi-tenant deployment; any deployment where the server is not operated by the vault's owner; a client surface that runs in a context where request bodies are visible to a third party (e.g. a third-party-hosted extension distribution with broad host permissions); or the point where rate limiting + KDF hardening have removed the other two P0s and wire-capture resistance is the largest remaining auth risk. At that point OPAQUE is the right next step and this plan's `credentials.rs` is the single place to replace.

### 4.3 SRP-6a — **REJECTED**
SRP would also stop replay (its stored verifier `v = g^x` is not presentable), so it is not absurd. But: it is not an aPAKE, so the stored verifier is still offline-dictionary-attackable — the same property that already exists via `vault_key_wrap`, so it buys nothing on the axis where it differs from hashing. And it needs bignum modexp implementations on the server *and* in both JS surfaces, with the classic SRP pitfalls (group parameter validation, `k` multiplier, timing). Large new attack surface for zero delta over a 30-line HMAC. Rejected.

### 4.4 Rename the wire field to `credential_proof` — **REJECTED**
Touches `LoginRequest`/`RegisterRequest` schemas on web + extension + recovery + import, both registration endpoints, and the rewrap payload, for no security change. The value really is still "the verifier"; the meaningful rename is the *column* (§3.1), which is where the confusion lived. Keep the wire name; document the distinction on `AuthRequest`.

### 4.5 Store `HMAC(salt, decoded_verifier_bytes)` and require canonical 32-byte base64 — **REJECTED (deferred to the bounds P0)**
Cryptographically identical. It would force every test fixture (`"dmVyaWZpZXI="`, 8 bytes) to become a valid 32-byte value across ~8 files and would duplicate the input-validation work of the request-bounds P0. Hashing the presented string keeps one credential = one exact byte sequence anyway (the hash pins the spelling), so no aliasing is introduced. Revisit when the bounds item lands.

### 4.6 Pepper the hash with a per-install secret (`SESSION_COOKIE_KEY`, as `pair.rs:45-52` does) — **REJECTED**
It protects only against an attacker who has the DB but not the process environment — and that attacker is already able to crack `vault_key_wrap`, which is the cheaper target. In exchange it adds a fatal operational coupling: rotating or losing that key would reject every password login on the install (recoverable only with each vault's recovery file). The pairing-code pepper is justified there because a 6-character code is low-entropy; a 256-bit verifier is not. Rejected.

### 4.7 Asymmetric proof-of-possession (sign a challenge with a key derived from the password, store the public key) — **REJECTED**
This is the only design that keeps the auth path free of *any* password-derived at-rest material, and it is a legitimate end-state. But it is a bespoke PAKE substitute: it needs a keypair per vault, a new envelope (or a widened password envelope), a challenge endpoint, rotation on every password change *and* on recovery rewrap, and a portable Ed25519 implementation on all three surfaces — the same protocol surface as OPAQUE with none of the review. If we are going to pay that, we should pay it for RFC 9807. Rejected in favour of §4.2's trigger.

### 4.8 Do nothing, document the risk — **REJECTED**
The item is a release gate and the fix is ~150 lines of server code with no client risk. The only reason to defer would be if a PAKE were imminent, and §4.2 explains why it is not.

---

## 5. Files to touch

### New

| Path | Purpose |
|---|---|
| `apps/server/src/credentials.rs` | `new_credential` / `accepts` / `acceptable` + KAT and unit tests. The single place the credential format lives. |
| `apps/server/migration/src/m20261028_000008_vault_verifier_hash.rs` | Add `verifier_salt`, `verifier_hash`; drop `vault_verifier`. |
| `plans/p0-verifier-replay.md` | This document. |

### Edit

| Path | Change |
|---|---|
| `apps/server/migration/src/lib.rs` | Register migration 8. |
| `apps/server/src/main.rs` | `mod credentials;` (near `:8`); startup credential audit after `Migrator::up` (`:222`). |
| `apps/server/src/entity/vault.rs` | Replace `vault_verifier` (`:17`) with `verifier_salt`/`verifier_hash`; rewrite the comment to say the stored value is a hash and why. |
| `apps/server/src/endpoints/auth.rs` | `accepts()` at `:99`; length guard at `:55-61`; comment on `AuthRequest.vault_verifier` (`:20`) that it is a preimage and is never stored. |
| `apps/server/src/endpoints/register.rs` | Hash at `:148`; validation at `:84-98`. |
| `apps/server/src/endpoints/vaults.rs` | Required verifier (`:25`, `:134`); hash on insert. |
| `apps/server/src/endpoints/recovery.rs` | Rewrap CAS write (`:849-866`); test assertions at `:1535`, `:2125`. |
| `apps/server/src/endpoints/update_vault_password.rs` | Write via helper (`:55`); comment pointing at the P1 item. |
| `apps/server/src/endpoints/update_vault.rs` | Test fixture (`:259`). |
| `apps/server/src/endpoints/cloud_endpoints.rs` | Test fixtures (`:1664`, `:1701`). |
| `apps/server/src/cloud/package.rs` | Test fixtures (`:201`, `:298`); note in the module comment that the package never carries a credential. |
| `apps/server/src/cloud/mirror.rs` | Test fixtures (`:1107`, `:1368`). |
| `apps/server/architecture.md` | `:9-12`: the server stores a keyed hash, not the verifier. |
| `apps/server/migration/README.md` | `:46`: `vault_verifier` → credential hash columns. |
| `apps/client/architecture.md` | `:17`, `:109-111`: note that the verifier crosses the wire but is stored only as a hash. |
| `AGENTS.md` | Line 3: "…`vault_verifier` HMAC (stored only as a salted HMAC)…". One clause. |
| `SECURITY_AND_FEATURE_ROADMAP.md` | Mark the item fixed with evidence; add a changelog entry; add §9.1 as its own open item. |

### Do not touch

- `packages/vault-core/src/crypto.ts` — the `auth-v1|` label, `computeAuthVerifier`, `createAuthKey`, and the HKDF labels are a **wire contract with every existing verifier**. Changing them invalidates every vault and every client simultaneously, for no benefit. If that ever changes it is a KDF-profile migration (roadmap line 56), not this item.
- `apps/client/**` and `apps/extension/**` — no code change. Only two docs.
- `apps/server/src/session_auth.rs` — session semantics are out of scope; the cookie still stores only `vault_id`.
- `apps/server/src/endpoints/recovery.rs` recovery *verifier* logic (`expected_proof`, `proof_is_valid`, `regenerate`, challenge lifecycle) — only the password-credential write inside rewrap changes. §9.1 is deliberately not fixed here.
- `recoveryAad` / Rule R1 / any `recovery_*` column. The rewrap write must keep touching exactly `salt`, `iterations`, `verifier_*`, `vault_key_wrap*`, `credential_version` — and nothing else.
- COOP/COEP (`main.rs:303-306`, `apps/client/public/_headers`) — still required by sqlite-wasm OPFS; this change does not touch headers.
- `get_crypto_params` response shape; the cloud package format (`PACKAGE_FORMAT_VERSION` stays 2).

---

## 6. Trust boundary: what this must not break

1. **Zero-knowledge.** The server still never receives the master password, the vault key, or plaintext. Nothing new crosses the wire; one thing stops being written at rest. This change *shrinks* the server's knowledge. The client must not start sending anything new — a review of the diff should show zero client changes.
2. **Session semantics.** `voult_session` still holds only `vault_id` (`session_auth.rs:6`); `establish_vault_session` still rotates via `renew()` (`:32-38`). No change to expiry, `SESSION_REQUIRED`, teardown, or the lock model. A failed `/auth` must still establish nothing.
3. **Per-vault namespacing.** Nothing in storage, OPFS, IndexedDB, or AAD changes. `vault.id` remains the only identity.
4. **Rule R1.** Recovery still wraps `vaultKeyRaw` directly; the rewrap write must remain confined to the password credential columns. Adding a column that the rewrap touches by accident is the one plausible way to break recovery with this change — the CAS update is the review point.
5. **`credential_version` CAS.** The credential rotation stays inside the existing single `UPDATE … WHERE credential_version = ?`. Do not add a second statement, do not bump `version`, do not touch `lock_epoch`.
6. **COOP/COEP.** Untouched; sqlite-wasm needs them.
7. **Enumeration and failure uniformity.** `/auth` must keep returning exactly `401 AUTH_FAILED` for: unknown vault, bad verifier, and a row with no credential hash. No new error code, no new log line containing a value or an id. A legacy row must look identical to a wrong password.
8. **New attack surface: none.** No endpoint is added. The stored hash is less sensitive than what it replaces. The only new failure mode is "a row with an empty hash can never authenticate", which is fail-closed by construction.
9. **Do not log either value.** Not the salt, not the hash, not the presented verifier, not the request body. `AGENTS.md:72` already forbids this; the new column makes it easy to violate accidentally in a DB-error path.

---

## 7. Phases

Each phase leaves the tree compiling and `cargo test` green.

### M0 — Foundation: credential module + one live call site

Scope: add `apps/server/src/credentials.rs` and `mod credentials;`. Include the pinned KAT, the salt/hash round-trip tests, the "two writes of the same verifier differ" test, the malformed-input tests, and the `MAX_VERIFIER_LEN` guard. Wire only `credentials::acceptable()` into the existing `/auth` pre-flight (`auth.rs:55-61`), so the module is live (no dead-code warning) and the length guard is enforced from day one. Storage is untouched; `/auth` still does the string compare.

Acceptance:
- `cd apps/server && cargo test credentials` passes; the full `cargo test` still passes with the same count plus the new tests.
- `cargo run` + a normal password login in the web app still succeeds (behaviour unchanged for every real verifier).
- `curl -X POST localhost:8080/api/auth -H 'content-type: application/json' -d "{\"vault_id\":\"$ID\",\"vault_verifier\":\"$(python3 -c 'print("a"*300)')\"}"` returns `400 INVALID_INPUT`, and a normal login is unaffected.

### M1 — The switch: schema, writers, reader

Scope: migration 8; entity; `register`, `vaults`, `auth`, `recovery` rewrap, `update_vault_password`; all fixtures. After this phase no code path can write a plaintext verifier — the column no longer exists, so the compiler proves it.

Acceptance (a fresh DB for the create/login checks; a copy of the **pre-fix** DB for the replay and legacy-row checks — see the no-backfill decision):
- Create a vault end to end (including the recovery-file interstitial), lock, unlock with the password → works. Extension connect + password unlock → works.
- `sqlite3 "$HOME/Library/Application Support/Voult/voult.db" "select id, verifier_salt, verifier_hash from vault;"` shows a 24-char salt and a 44-char hash, and **no column contains the verifier**. Capture the value from DevTools (Network → `POST /api/auth` → request JSON) and confirm `select count(*) from vault where verifier_hash like '%<captured>%';` → `0`.
- **Replay test (the point of the item).** Before running the migration, copy the pre-fix DB and record `select vault_verifier from vault;`. After migrating, replay it:
  `curl -i -X POST localhost:8080/api/auth -H 'content-type: application/json' -d '{"vault_id":"<id>","vault_verifier":"<old value>"}'` → `401 {"code":"AUTH_FAILED"}`. The correct current verifier → `200` and a usable cookie (`GET /api/get_vault` → 200).
- Recovery: run the recovery flow with the saved file, set a new password, then log in with the new password → works. Log in with the old password → `401`.
- Legacy row: start the migrated server against the old DB copy; the orphaned vault returns `401 AUTH_FAILED` (not a 500) and startup logs exactly one warning with a count.
- `cargo test` green; `cd apps/client && npx tsc --noEmit` green with zero source changes (proves the client was not touched).

### M2 — Regression tests + documentation

Scope: cross-endpoint integration tests in `auth.rs` using the existing `test_app!`/`authenticated_app!` pattern (`update_vault.rs:224-280`): register → `/auth` 200 + cookie → `/get_vault` 200; wrong verifier → 401 and **no** `vault_key_wrap` in the body; a rewrap in `recovery.rs` then `/auth` with the new verifier → 200 and with the old → 401. Add the "the row does not contain the submitted value" assertion next to the register test. Update the docs listed in §5.

Acceptance:
- `cargo test` green, including a named test whose failure message is "the plaintext verifier must not be recoverable from the row".
- `rg -n "stores? the verifier|vault_verifier" apps/server/architecture.md apps/server/migration/README.md AGENTS.md` returns only statements that are still true (wire-level), and the roadmap item is marked with file:line evidence.
- No new log line in the diff contains a verifier, hash, or vault id: `git diff | rg -i "log.*(verifier|hash)"` reviewed by hand.

### M3 — Hardening / store-readiness

Scope: the startup audit (§3.6); a comment block on `StoredCredential` and on `auth.rs` stating the pass-the-hash invariant ("the client sends the preimage; the server hashes on arrival; never add a path that accepts the stored value"); a final pass for `Debug` derives or `{:?}` formatting that could print the hash.

Acceptance:
- Start the server against a DB containing one pre-migration vault → exactly one `warn` line with a count and no identifiers; all other vaults unaffected.
- Start against a clean DB → no warning.
- `rg -n "derive\(.*Debug" apps/server/src/credentials.rs` returns nothing, or the struct has a manual `Debug` that redacts.
- `cargo test` green; manual smoke of M1's checklist still passes.

---

## 8. How to verify the claim in two commands

After M1, with the server running and the client logged in, this must print `0`:

```sh
V='<the vault_verifier value from the browser Network panel>'
sqlite3 "$HOME/Library/Application Support/Voult/voult.db" \
  "select count(*) from vault where verifier_hash = '$V' or verifier_salt = '$V';"
```

And this must print `401`:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/api/auth \
  -H 'content-type: application/json' \
  -d "{\"vault_id\":\"<id>\",\"vault_verifier\":\"$V\"}"
```

(The second command fails *because* `$V` is the preimage and the server hashes it — if it ever returns 200, someone has added a path that compares the stored hash to the presented value. That is the pass-the-hash regression this item must never acquire.)

---

## 9. Out of scope, stated explicitly

### 9.1 Adjacent finding: `recovery_verifier` is a plaintext MAC key

`expected_proof` uses the stored `recovery_verifier` as the HMAC key (`recovery.rs:192-198`) and `/recovery/rewrap` is unauthenticated (`main.rs:330-336`). Therefore a DB-dump attacker can mint a valid proof for a fresh challenge and call `rewrap` with a self-chosen `new_vault_key_wrap`, obtaining a session and the ability to overwrite the row's ciphertext. This grants **no plaintext** (they cannot construct an envelope containing the real vault key, and `recovery_wrap` still holds it under K_rec, so the recovery file can restore the vault) — it is a recoverable destructive reset, not a confidentiality break.

Not fixed here, deliberately: hashing `recovery_verifier` is impossible without making its hash the credential (pass-the-hash), and the real fix is asymmetric proof-of-possession over the vault key, which is a different design. Recorded so that "the verifier P0 is closed" is not read as "a DB dump is now harmless". Recommend adding it to the roadmap as its own item.

### 9.2 Everything else
Online guessing (`/auth` has no rate limit — separate P0), offline cracking cost (PBKDF2 60k — separate P0), request/protocol bounds (separate P0), account enumeration via `get_crypto_params` (separate P1), the unwired and unsafe `/vault/password` semantics (separate P1), wire-capture resistance (OPAQUE trigger, §4.2), DB-write access (game over by definition — an attacker who can write the row can write their own hash).

---

## 10. Decisions log

| # | Decision | Rationale | Evidence |
|---|---|---|---|
| 1 | Salted HMAC at rest, not a PAKE | Closes the stated harm completely; OPAQUE's marginal benefit against a DB dump is zero given the envelope, and its cost includes breaking the single-write recovery rewrap. Confirmed with the owner. | §1.1, §4.2, `crypto.ts:310-334` |
| 2 | Keep the wire contract and field names | Zero client/extension diff; the verifier value is unchanged, only its storage is | `auth.rs:14-21`, `flows.ts:182-184` |
| 3 | Hash `voult-verifier-v1\|` + the presented **string** | Preserves exact-match semantics, pins one credential per spelling, avoids duplicating the bounds P0 | §4.5 |
| 4 | Fresh 16-byte random salt per credential write | Standard stored-verifier shape and free; **not** claimed as a security boundary (the verifier is already per-vault and 256-bit) | §3.1 |
| 5 | Drop `vault_verifier`; do not reuse the name | A column named `vault_verifier` holding a hash is the confusion this item removes; dropping makes the compiler find every writer | `entity/vault.rs:17` |
| 6 | No backfill; existing dev vaults fail closed | A backfill would re-implement the credential hash inside the migration crate for pre-release data only; repo precedent is "breaking change, delete the dev DB" | `migration/src/lib.rs:5-8` |
| 7 | Column names `verifier_salt` / `verifier_hash` | Self-describing; no `vault_` prefix collision with the recovery columns | §3.1 |
| 8 | Rewrap derives the new credential inside the existing CAS update | No window with a half-written credential; `credential_version` semantics untouched | `recovery.rs:849-866` |
| 9 | `/vaults` verifier becomes required | Today it can create an empty, unloginable credential; the endpoint is unreferenced by the client | `vaults.rs:25`, `:134` |
| 10 | `update_vault_password` routes through the helper only | Stops plaintext writes without absorbing the P1 rewrap work | `update_vault_password.rs:55`, roadmap line 71 |
| 11 | Startup audit logs a count, not ids | Operational honesty after the breaking migration; log sanitisation P0 forbids ids | §3.6, `main.rs:222` |
| 12 | Do not touch `crypto.ts` labels | Changing the derivation invalidates every verifier on every surface | `crypto.ts:185-194` |
| 13 | Recovery-verifier forgery is documented, not fixed | Different mechanism, different fix; fixing two items in one change was explicitly excluded | §9.1 |

---

## 11. Implementation record (2026-10-29)

Implemented across M0–M3 with no deviation from the design above and **zero
source changes under `apps/client` or `apps/extension`**.

Verification actually run:

| Check | Result |
|---|---|
| `cargo test` (`apps/server`) | 112 passed, 0 failed (was 100; +7 `credentials` unit tests, +5 `auth` integration tests) |
| `cargo fmt --check` | clean |
| Fresh DB: register → `/auth` → `/get_vault` | `201` → `200` → `200` |
| Wrong verifier | `401 AUTH_FAILED`, no session cookie, no `vault_key_wrap` in the body |
| **Stored `verifier_hash` presented as the credential** | `401` — pass-the-hash is blocked |
| DB shape | `verifier_salt` 24 chars (16 B), `verifier_hash` 44 chars (32 B) |
| Plaintext verifier anywhere in the SQLite file (`grep -a -F`) | 0 matches |
| Migration 8 on a simulated **pre-migration** DB (old column, real value) | applies on a non-empty table; the old plaintext is gone from the file (0 raw matches, 0 free pages); replaying the old stored value → `401` |
| Migrated row (empty credential pair) | `401 AUTH_FAILED` (not 500), and one startup `warn` with a count and no ids |
| Clean DB startup | no audit warning |
| Restart after migration (idempotency) | server starts, sessions behave, legacy row still fails closed |

Note for the reviewer: migration 8 deliberately backfills nothing, so any
development vault created before this change can no longer log in by password
(recovery still works — the `recovery_*` columns are untouched). Delete the dev
DB (`~/Library/Application Support/Voult/voult.db`) and recreate the vault.
