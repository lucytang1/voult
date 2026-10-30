# P0 — Enforce request/protocol bounds at every write boundary

**Status:** implemented on `p0/request-bounds` (M0–M4; see §11 for the as-built notes).
**Roadmap item:** `SECURITY_AND_FEATURE_ROADMAP.md:61` ("P0 — Enforce request/protocol bounds at every write boundary").
**Worktree / branch:** `p0-request-bounds`.
**Scope:** the server writes that persist vault credential material or vault ciphertext, plus the one client path that consumes attacker-influenced crypto parameters (cloud import).

---

## 1. Definition of done

A write is accepted only if every field matches the exact wire shape this codebase's own readers assume, or it is refused **before any DB work** with the existing `{"error_msg", "code"}` envelope. Concretely:

1. Every field of `POST /api/register`, `/api/vaults`, `/api/auth`, `/api/update_vault`, `/api/vault/password`, `/api/recovery/*`, and the ciphertext/package-carrying cloud writes is covered by an explicit rule in §3.3 — no field is "whatever serde accepts".
2. `crypto_version` is an allow-list (`2`), and no write can change it.
3. `iterations` is bounded on every write that stores it, from **one** server-side module.
4. Every salt / IV / verifier / wrap / proof / challenge is exact-length canonical base64; every vault id is a canonical UUID v4.
5. Vault ciphertext has a chosen maximum, and the JSON body has an explicit maximum that provably exceeds the largest legitimate request.
6. The client refuses to *generate* an oversized vault and refuses to *derive* from out-of-range params, so the server's new 400s are a backstop rather than the user's first warning.
7. `cargo test`, `npm test` in `packages/vault-core`, and `npx tsc --noEmit` in both `apps/client` and `apps/extension` are green, and the manual matrix in §8 passes.

---

## 2. Research: what the code does today

### 2.1 Is the roadmap claim still accurate?

Mostly yes. Three corrections:

- **"…and any cross-instance body limit" is stale as written.** A body limit already exists: `endpoints::json_config()` is `web::JsonConfig::default()` and never calls `.limit()` (`apps/server/src/endpoints/mod.rs:34-55`), so Actix's default **2 MiB** applies (actix-web 4.12.1, `types/json.rs:279`). The overflow path is already mapped to `413 PAYLOAD_TOO_LARGE` with the JSON envelope (`mod.rs:39-43`), installed at `main.rs:318`. The real problem is that the limit was never *chosen*: it silently caps a vault at ≈1.5 MiB of ciphertext (base64 inside a 2 MiB body), and a vault that grows past it fails sync with a raw 413 (`apps/client/src/lib/sync/index.ts:170-180`).
- **"before opening a transaction"** is accurate for `/register` (`register.rs:86-124` validates, `:127` begins the transaction) but misleading for `/vaults`, which never opens a transaction at all and validates *after* an existence `SELECT` (`vaults.rs:69-77` runs before `:79-103`). Also, "reject blanks" is not "validate shape": presence is checked, lengths and alphabets are not.
- **"Every recovery failure returns one identical `401 AUTH_FAILED`"** (AGENTS.md and the recovery item) is true for a *well-formed but wrong* proof, and is pinned only on `/recovery/unlock` (`unlock_failures_are_byte_identical`, `recovery.rs:1446-1503`). `/recovery/rewrap` and `/recovery/regenerate` return `400 INVALID_INPUT` for a malformed body (wrong proof length, bad salt length) and `401` for a wrong proof (`:758-760`, `:1008-1010`). That is caller-side information and not an oracle, but the blanket claim is inaccurate; do not "fix" it by turning body-shape failures into 401s.

Everything else checks out: `/recovery/rewrap` validates canonical ids, exact base64 lengths and a bounded KDF count before `pool.begin()` (`recovery.rs:754-801`); `/recovery/regenerate` does the same (`:993-1036`); `/auth`, `/update_vault`, `/vault/password` have no shape validation at all; there is no ciphertext cap anywhere.

### 2.2 Defects found while verifying (these are the actual work)

**F1 — `/register` can create a vault that can never be recovered or backed up.**
`crypto_version` is `Option<i32>` defaulting to `1` (`register.rs:25-26`, `:125`) while the same request is required to carry a v2-shaped password envelope (`:96-102`). A row with `crypto_version = 1` is refused by `package::build` (`cloud/package.rs:141-151`, returns `LEGACY_CRYPTO`) and by `recovery/rewrap` (`recovery.rs:835-846`). It opens with a password but can never be backed up or recovered. `/vaults` defaults to `2` (`vaults.rs:127`) — the two creation endpoints disagree.

**F2 — `/vaults` stores an empty verifier when the field is omitted.**
`vault_verifier: Set(req.vault_verifier.unwrap_or_default())` (`vaults.rs:134`) writes `""`. `/auth` rejects a blank verifier (`auth.rs:55-61`), so the row can never authenticate again. Permanent, silent brick.

**F3 — `/update_vault` can write half of a password envelope.**
`vault_key_wrap.or(old)` and `vault_key_wrap_iv.or(old)` (`update_vault.rs:95-98`) mean a request carrying only one of the pair stores the new value next to the old one. The result cannot be unwrapped by any password, and there is no endpoint that repairs it. The same handler also accepts an arbitrary `crypto_version` on every document write (`:94`, `:106-109`).

**F4 — `/update_vault`'s version arithmetic overflows.**
`version: u32` is cast to `i32` for the CAS filter (`update_vault.rs:123`) and then `request.version + 1` (`:150`). `version = u32::MAX` panics in a debug build and wraps in release; anything above `i32::MAX` can never match the stored column.

**F5 — `/vault/password` can brick a vault by construction.**
It accepts `new_salt` / `new_iterations` and writes them without receiving a matching password-wrapped vault-key envelope (`update_vault_password.rs:54-62`). The next unlock derives the wrapping key from the **new** salt and fails to unwrap the **old** envelope. No client calls this route (verified: the only `vault/password` reference in the repo is its own definition), so nothing is lost by restricting it.
*Overlap:* the P1 item "Complete password-change protocol atomically" owns the real fix. This plan only closes the unsafe shape.

**F6 — `/auth` enforces no credential shape.**
Only "non-blank" plus a UUID parse (`auth.rs:55-69`), then a plain `!=` comparison (`:99`). A one-character verifier is storable and accepted, so "the verifier is a 256-bit MAC" is a client convention rather than a server-enforced invariant. (Constant-time comparison and replay resistance are a *different* P0 — see §9.)

**F7 — Creation endpoints accept values no reader can consume.**
`/register` and `/vaults` check presence only (`register.rs:86-115`, `vaults.rs:79-103`). A 4-byte salt, a 2-byte IV, a 3-byte envelope IV, or non-base64 ciphertext is stored. The readers assume exact shapes: `recovery.rs:219-227` (`decode_exact`), and the client's `fromB64` → `atob` throws (`packages/vault-core/src/crypto.ts:74-76`). The row is created successfully and is unrestorable.

**F8 — No ciphertext cap, and the implicit transport cap is unusable as a product limit.**
Nothing bounds `vault` other than the body limit. See §2.1: ≈1.5 MiB of ciphertext today, reached by a few thousand items, with no client-side warning.

**F9 — The cloud-import path derives from unvalidated, attacker-influenceable params.**
`importVaultFromCloud` reads `iterations` from the package and passes it straight into `derivePasswordWrappingKey` (`apps/client/src/lib/vault/import.ts:105-126`) before anything validates it. `iterations: 2147483647` freezes the tab in PBKDF2 with no cancel. The server check (registration) happens *after* the expensive derivation (`:164-183`), so it is not a defence here.

### 2.3 What is already correct — do not regress

- Recovery validates exact base64 lengths and a bounded KDF before any mutation (`recovery.rs:754-799`, `:993-1034`), and burns the challenge inside the transaction (`:408-422`).
- Every recovery **proof** failure on `/recovery/unlock` is one identical `401 AUTH_FAILED` (`recovery.rs:157-170`), pinned by `unlock_failures_are_byte_identical` (`:1446-1503`). Rewrap/regenerate keep their existing split: 400 for a malformed body, 401 for a wrong proof.
- Deserialization failures already return the documented envelope (`mod.rs:34-55`).
- Vault identity is always session-derived on writes (`session_auth.rs:6-14`); `vault_id` in a body is only ever a consistency check.
- `cache-control: no-store` on `/api/*` and COOP/COEP on all responses (`main.rs:300-318`).

---

## 3. The contract

### 3.1 Constants — one definition per language

Server: new `apps/server/src/endpoints/validate.rs` (declared in `endpoints/mod.rs`).
Client/shared: new `packages/vault-core/src/bounds.ts`, re-exported from `packages/vault-core/src/index.ts`.

| Constant | Value | Derivation / why |
|---|---|---|
| `SALT_LEN` | 16 B | `generateSalt()` allocates 16 (`packages/vault-core/src/crypto.ts:34-39`); used for both the PBKDF2 salt and the recovery HKDF salt (`:34-39`, `:476-483`). |
| `IV_LEN` | 12 B | 96-bit GCM nonce in `encrypt` and `wrapKeyBytes` (`crypto.ts:202`, `:262`). |
| `VERIFIER_LEN` | 32 B | HMAC-SHA256 output (`crypto.ts:179-194`, `:495-503`). |
| `KEY_WRAP_LEN` | 48 B | 32-byte `vaultKeyRaw` (`crypto.ts:235-238`) + 16-byte GCM tag (`:256-277`). Applies to both the password and the recovery envelope. |
| `PROOF_LEN` | 32 B | HMAC-SHA256 (`crypto.ts:515-523`). |
| `CHALLENGE_LEN` | 32 B | server-minted 256-bit challenge (`recovery.rs:559-561`). |
| `MIN_CIPHERTEXT_LEN` | 17 B | GCM tag (16) + at least one byte of payload. The real minimum document is ~40 bytes of JSON; this is a sanity floor, not a document check. |
| `MAX_CIPHERTEXT_LEN` | 4 MiB (4,194,304 B) | Chosen blob ceiling. ≈6,000 average items; keeps one full-document CAS rewrite plus the post-commit mirror bounded. See D5 for the rejected alternatives. |
| `MAX_PACKAGE_LEN` | 6 MiB (6,291,456 B) | `base64(MAX_CIPHERTEXT_LEN)` = 5,592,408 chars + envelope metadata (`cloud/package.rs:162-185`). 6 MiB leaves ~690 KB headroom. |
| `MAX_REMOTE_ID_LEN` | 512 chars | Provider file ids / revisions (`cloud_endpoints.rs:1213-1218`, `:1084-1090`). Opaque identifiers; 512 is far above any provider's. |
| `KDF_ITERATIONS_MIN` | 60,000 | The value every client writes today (`packages/vault-core/src/crypto.ts:12-15`) and the floor recovery already enforces (`recovery.rs:68-70`). It is a **write-time** floor. |
| `KDF_ITERATIONS_MAX` | 2,000,000 | Bounds the cost the *client* pays on every unlock, because the client runs PBKDF2 with the server-supplied count. Kept identical to `recovery.rs:71-73` so this plan does not move the ceiling — moving it is the KDF-profile item's job. |
| `SUPPORTED_CRYPTO_VERSION` | 2 | The only version any producer emits (`crypto.ts:14`, `apps/client/src/lib/auth/flows/signup.ts:92`, forwarded on restore at `apps/client/src/lib/vault/import.ts:171`). |
| `MAX_JSON_BODY_BYTES` | 12 MiB (12,582,912 B) | `base64(MAX_PACKAGE_LEN)` = 8,388,608 chars + JSON framing (the request field is base64 of a package whose ciphertext is already base64). 12 MiB covers it with ~4 MB headroom. |

Client-side only, in `bounds.ts`: `KDF_READ_FLOOR = 60_000` — the absolute floor for *deriving* from an existing row (see D8); today it equals `KDF_ITERATIONS_MIN`, and the two diverge when the KDF-profile item raises the write floor without invalidating existing vaults. The client exposes the ciphertext cap as `MAX_VAULT_CIPHERTEXT_BYTES`; it is the same number as the server's `MAX_CIPHERTEXT_LEN`.

### 3.2 The three shape rules

**Canonical UUID.** `s.trim()` parses as a UUID, `Uuid::to_string() == s.trim()`, and `get_version_num() == 4`. This rejects uppercase, braced, and unhyphenated spellings (they would name the same row under a different string) and nil/non-v4 ids. Every producer is `crypto.randomUUID()` (`crypto.ts:46-68`) or `uuidv4()` (`apps/client/src/lib/crypto/vault.ts:18-26`).

**Canonical base64.** Standard alphabet (`A–Z a–z 0–9 + /`), padded to a multiple of 4, **canonical trailing bits**, no interior whitespace; outer whitespace is trimmed. This is exactly what `base64 0.22`'s `STANDARD` engine accepts (`GeneralPurposeConfig::new()` → `RequireCanonicalPadding`, `decode_allow_trailing_bits = false`) and what the client produces via `btoa` (`crypto.ts:70-72`). Reject URL-safe (`-_`) and unpadded forms. In TypeScript do **not** canonicalise with `btoa(atob(s))`: spreading a 4 MiB array into `String.fromCharCode` overflows the stack. Check the last quantum's trailing bits directly.

**KDF range.** `KDF_ITERATIONS_MIN <= iterations <= KDF_ITERATIONS_MAX`. Negative and zero are rejected by the same range check.

### 3.3 Per-endpoint matrices

Legend: **400** = `{"error_msg":"<field> must be <expected>","code":"INVALID_INPUT"}`. Every check below runs before any DB read/write except where a row is explicitly needed (noted).

#### `POST /api/register` (unauthenticated)

| Field | Accepts | On violation |
|---|---|---|
| `vault_id` | canonical UUID v4 | 400 `vault_id must be a canonical UUID v4` |
| `vault_verifier` | base64, exactly 32 B | 400 `… must be 32 bytes of base64` |
| `salt` | base64, exactly 16 B | 400 |
| `iterations` | 60,000–2,000,000 | 400 `iterations must be between 60000 and 2000000` |
| `vaultiv` | base64, exactly 12 B | 400 |
| `vault` | base64, 17 B–4 MiB decoded | 400 `vault must be between 17 and 4194304 decoded bytes of base64` |
| `crypto_version` | required, exactly `2` | 400 `crypto_version must be 2` |
| `vault_key_wrap` | base64, exactly 48 B | 400 |
| `vault_key_wrap_iv` | base64, exactly 12 B | 400 |
| `recovery_verifier` | base64, exactly 32 B | 400 |
| `recovery_salt` | base64, exactly 16 B | 400 |
| `recovery_wrap` | base64, exactly 48 B | 400 |
| `recovery_wrap_iv` | base64, exactly 12 B | 400 |

Order: shape checks → `pool.begin()` (`register.rs:127`). Existing blank checks are subsumed; keep the "required" message only where a field is absent (serde already produces that through `json_config`).

#### `POST /api/vaults` (session)

Same rules as `/register` for every crypto field (the twelve non-`vault_id` fields), plus the `vault_id` rule below:

| Field | Accepts | On violation |
|---|---|---|
| `vault_id` | optional; if present canonical v4 **and** equal to the session vault | 400 (`invalid`) / 403 `VAULT_MISMATCH` (existing) |
| `vault_verifier` | **required**, base64 32 B (no `unwrap_or_default`) | 400 |
| `crypto_version` | required, exactly `2` | 400 |

Note: this route is effectively unreachable today — a session only exists for an already-registered vault, so the existence check at `vaults.rs:69-77` always wins. It is still hardened: the route is live, and the invariant must not depend on nobody calling it.

#### `POST /api/auth` (unauthenticated)

| Field | Accepts | On violation |
|---|---|---|
| `vault_id` | canonical UUID v4 | 400 |
| `vault_verifier` | base64, exactly 32 B | 400 |

Uniformity preserved: an unknown vault and a wrong (but well-formed) verifier both return `401 AUTH_FAILED` with the same body (`auth.rs:78-105`). A *malformed* verifier is caller-side and reveals nothing about the row, so 400 is safe. Compare the **trimmed** request value against the stored value.

#### `POST /api/update_vault` (session)

| Field | Accepts | On violation |
|---|---|---|
| `vault` | base64, 17 B–4 MiB decoded | 400 |
| `vaultiv` | base64, exactly 12 B | 400 |
| `version` | integer, 1 ≤ v ≤ 2,147,483,646 | 400 `version must be between 1 and 2147483646` |
| *(removed)* `crypto_version` | must not be sent — `#[serde(deny_unknown_fields)]` | 400 from serde via `json_config` |
| *(removed)* `vault_key_wrap` | must not be sent | 400 |
| *(removed)* `vault_key_wrap_iv` | must not be sent | 400 |

After loading the row: if `vault.crypto_version != 2` → `409 UNSUPPORTED_CRYPTO_VERSION` (same code and shape as `recovery.rs:841-846`). The update statement writes **only** `vault`, `vaultiv`, `version` (§F3). `new_version = request.version.checked_add(1)` — the bound makes the cast at `:123` safe and the add infallible, but keep `checked_add` with a `500 DATA_INTEGRITY_ERROR` fallback so a future bound change cannot reintroduce F4.

#### `POST /api/vault/password` (session)

| Field | Accepts | On violation |
|---|---|---|
| `new_vault_verifier` | base64, exactly 32 B | 400 |
| `new_salt` | must be absent | 409 `PASSWORD_CHANGE_REQUIRES_REWRAP` |
| `new_iterations` | must be absent | 409 `PASSWORD_CHANGE_REQUIRES_REWRAP` |

The 409 message: "changing salt or iterations requires the atomic rewrap flow". `error_msg` names both fields once. Nothing is written. Rationale and alternatives: D4.

#### `POST /api/recovery/challenge` (unauthenticated)

| Field | Accepts | On violation |
|---|---|---|
| `vault_id` | canonical UUID v4 (unchanged behaviour) | 400 |

#### `POST /api/recovery/unlock` (unauthenticated)

| Field | Accepts | On violation |
|---|---|---|
| `vault_id` | canonical UUID v4 | 400 (unchanged) |
| `selector` | canonical UUID (36 chars) | **401 AUTH_FAILED** — same bytes as every other proof failure |
| `proof` | base64, exactly 32 B | **401 AUTH_FAILED** (unchanged, `recovery.rs:640-642`) |

The selector pre-check exists only to avoid a DB query for a value that cannot match; it must **not** become a 400, or `unlock_failures_are_byte_identical` and the no-oracle rule break. See D9.

#### `POST /api/recovery/rewrap`

| Field | Accepts | On violation |
|---|---|---|
| `vault_id` | canonical v4 | 400 (existing) |
| `selector` | canonical UUID | **401 AUTH_FAILED** (pre-check, same as unlock) |
| `proof` | base64 32 B | 400 (existing) |
| `credential_version` | integer ≥ 0 | 400 (existing) |
| `new_salt` | base64 16 B | 400 (existing) |
| `new_iterations` | 60,000–2,000,000 | 400 (existing; constants move to `validate.rs`) |
| `new_vault_verifier` | base64 32 B | 400 (existing) |
| `new_vault_key_wrap` | base64 48 B | 400 (existing) |
| `new_vault_key_wrap_iv` | base64 12 B | 400 (existing) |

Plus the existing post-proof `crypto_version == 2` guard (`recovery.rs:833-846`).

#### `POST /api/recovery/regenerate`

| Field | Accepts | On violation |
|---|---|---|
| `vault_id` | canonical v4 **and** equal to session | 400 / 403 (existing) |
| `selector` | canonical UUID | **401 AUTH_FAILED** (pre-check) |
| `proof` | base64 32 B | 400 (existing) |
| `new_recovery_verifier` | base64 32 B | 400 (existing) |
| `new_recovery_salt` | base64 16 B | 400 (existing) |
| `new_recovery_wrap` | base64 48 B | 400 (existing) |
| `new_recovery_wrap_iv` | base64 12 B | 400 (existing) |

#### Ciphertext-carrying cloud writes (session)

| Endpoint | Field | Accepts |
|---|---|---|
| `POST /api/cloud/vaults/create` | `vault_id` | canonical v4 and equal to session (400 / 403) |
| | `package` | encoded ≤ 8,388,608 chars; decoded ≤ 6 MiB; `parse_header` must succeed (`cloud/package.rs:120-130`) |
| `POST /api/cloud/vaults/replace` | `vault_id` | optional; if present canonical and equal to session (today it is only a presence flag, `:1122`) |
| | `package` | same as create |
| | `file_id`, `if_match_revision` | ≤ 512 chars |
| `POST /api/cloud/vaults/delete` | `file_id`, `vault_id` | ≤ 512 / canonical v4 |
| `POST /api/cloud/binding` | `vault_id` | canonical v4 and equal to session (`:1235-1245`) |
| | `remote_file_id`, `remote_revision` | ≤ 512 chars |

These routes are not called by the current client (enrollment is server-side, `apps/client/src/lib/cloud/enableSync.ts:34-65`), so there is no UX cost. They remain live write boundaries that persist ciphertext at a provider.

#### Deliberately out of scope (see §10)

`POST /api/pair/consume` already normalises and length-checks its code (`pair.rs:220-228`); `/lock`, `/logout`, `/pair/start` have no body; `/cloud/auth/*`, `/cloud/disconnect`, `/cloud/link-pending` carry provider metadata whose storage hardening is P1.

### 3.4 Status rules

| Situation | Status | Code |
|---|---|---|
| A field does not match its shape | 400 | `INVALID_INPUT` |
| The body is larger than `MAX_JSON_BODY_BYTES` | 413 | `PAYLOAD_TOO_LARGE` (existing mapping) |
| A well-formed value describes an unsupported protocol state | 409 | `UNSUPPORTED_CRYPTO_VERSION` / `PASSWORD_CHANGE_REQUIRES_REWRAP` |
| A recovery proof is wrong, missing, or malformed on the unlock path | 401 | `AUTH_FAILED` (unchanged) |

413 is reserved for "the transport refused to read the body"; an oversized *field* inside a readable body is a 400. This keeps axios's error handling from classifying a validation failure as a transport failure (`apps/client/src/lib/queries/http.ts:41-45`).

### 3.5 Ordering rule

**Session → shape → DB.** A session-protected write returns `401 SESSION_REQUIRED` before it looks at the body, because the client's teardown path keys on exactly that (`http.ts:47-56`); returning 400 for a session-less request would leave the app thinking it is still authorised. Within the handler, every shape check precedes the first `SELECT`.

### 3.6 Where the numbers live (the KDF-profile seam)

- Server: `apps/server/src/endpoints/validate.rs` is the only module allowed to contain a length, an iteration bound, or a supported version. Endpoint modules call `validate::…`; they never compare against a literal.
- Client/shared: `packages/vault-core/src/bounds.ts` is the mirror. `crypto.ts` imports `assertKdfParams` from it; no other file hard-codes an iteration number.
- Cross-language duplication is unavoidable (Rust vs TS) and is pinned three ways: a unit test in each language asserting the literals, an invariant test in Rust asserting `base64_len(MAX_CIPHERTEXT_LEN) < MAX_PACKAGE_LEN` and `base64_len(MAX_PACKAGE_LEN) < MAX_JSON_BODY_BYTES`, and the table in `docs/request-bounds.md` as the human-readable contract.
- When the KDF-profile P0 lands it changes `KDF_ITERATIONS_MIN`/`MAX` (and `PBKDF2_ITERATIONS`) in these two files only. If that item replaces PBKDF2 with a memory-hard KDF, `iterations: i32` stops being the right field; that item owns the descriptor change, the column, and the client migration. **This plan does not add a profile field, a version field, or a migration.**

---

## 4. Decisions (alternatives and verdicts)

**D1 — One validation module, primitives + `FieldError`.**
Chosen: `endpoints/validate.rs` with `FieldError { field, expected }` and `uuid_field / b64_exact_field / b64_bounded_field / kdf_field / crypto_version_field`, each returning `Result<(), FieldError>`; each endpoint gets one `fn validate_x(req: &XRequest) -> Result<(), FieldError>` called at the top of the handler.
Rejected: inline checks per handler (this is how F1–F7 happened; the roadmap's own wording is "do not grow a second dialect"). Rejected: validating newtypes at deserialization (`#[serde(try_from)]`) — stronger by construction, but the error becomes a generic serde string and the client loses the field-specific `error_msg` it displays; also a much larger diff for ten endpoints. Rejected: a validator crate (`validator`, `garde`) — a new dependency on the security path to express a fixed table of lengths.

**D2 — `crypto_version` is required and must be `2`.**
Chosen: no default on `/register`, required on `/vaults`, allow-list of one value, and no write may change it.
Rejected: default to `2` — hides a missing statement in a field that selects how the ciphertext is interpreted. Rejected: allow `{1, 2}` — no producer emits 1 (`signup.ts:92`, and the cloud-restore path forwards the package's version at `import.ts:171`), a v1 row has no envelope, cannot be backed up (`cloud/package.rs:146-150`) and cannot be rewrapped (`recovery.rs:835`). There are no releases, so dropping v1 is a code change, not a migration.

**D3 — `/update_vault` shrinks to `{ vault, vaultiv, version }`.**
Chosen: remove `crypto_version`, `vault_key_wrap`, `vault_key_wrap_iv` from the request and from the shared `UpdateVaultRequest` type (`packages/vault-core/src/schema.ts:570-577`); add `#[serde(deny_unknown_fields)]` so an obsolete client gets a loud 400 instead of a silent no-op.
Rejected: keep the fields and validate pairing — it would leave a second writer for credential material that has no proof of the master password and no atomicity with `credential_version`, i.e. the exact F3 hazard. Both current writers already send only the three fields (`apps/client/src/lib/sync/index.ts:170-173`, `apps/extension/src/background/vault.ts:1418-1421`), so nothing breaks.

**D4 — `/vault/password` rotates the verifier only.**
Chosen: reject any presence of `new_salt`/`new_iterations` with `409 PASSWORD_CHANGE_REQUIRES_REWRAP`, pointing at the P1 atomic flow. A verifier-only rotation (same salt, same iterations, same envelope) is safe and remains possible.
Rejected: validate the ranges and keep accepting — satisfies the letter of the roadmap while leaving F5 in place; a validated salt change still strands the envelope. Rejected: delete the route — it is the natural landing place for the P1 flow, and deleting it would remove the shape that flow will extend. Rejected: leave it alone — it is an unused session endpoint that can permanently destroy a vault's password path.

**D5 — Caps: 4 MiB ciphertext, 6 MiB package, 12 MiB body.**
Chosen: 4 MiB of ciphertext is ≈6,000 average items, keeps one full-document CAS rewrite and one mirror package under a few seconds, and fits inside a 12 MiB body even when a package is base64-encoded twice (ciphertext → base64 inside the package → base64 for transport ≈ 7.46 MB).
Rejected: 2 MiB ciphertext — that is essentially today's accidental ceiling (~1.5 MiB), so it would codify the bug instead of fixing it. Rejected: 16 MiB — every edit rewrites and re-mirrors the whole blob, and it makes the unauthenticated `/register` disk-fill cheaper per request. Rejected: no cap — the roadmap item exists because of this. Rejected: per-item sync (the real long-term answer) — it needs a new table, new merge semantics and a schema change; it belongs to its own plan.
**Assumption and fallback:** 4 MiB is a judgement call, not a measurement. If a real vault approaches it, raise the single constant (and `MAX_PACKAGE_LEN`/`MAX_JSON_BODY_BYTES` follow by the invariant test). If the ceiling is being hit routinely, the fix is per-item sync, not a bigger blob.
*Honest delta:* this raises the maximum storable bytes per unauthenticated `/register` request from ≈1.5 MiB to 4 MiB. Request *count* is unbounded either way; bounding it is the rate-limiting P0 (§9).

**D6 — Field-cap violations are 400, not 413.**
Chosen: 400 `INVALID_INPUT`. Rejected: 413 for an oversized `vault` field — it conflates "I could not read the body" with "I read it and a field is too big", and the client's network-error classifier would treat it as a transport problem.

**D7 — Client refuses oversized documents, but leaves intents pending.**
Chosen: after `encrypt()` in `apps/client/src/lib/sync/index.ts:160-168` and before `postUpdateVault` in the extension (`background/vault.ts:1415-1421`), compare `cipher.length` with `MAX_VAULT_CIPHERTEXT_BYTES`; if over, log one `error` line with the size and cap (never the content) and return without pushing. Intents keep `synced = 0, error IS NULL`.
Rejected: `markIntentError` — it removes the intents from `fetchPendingIntents` (`intent-service.ts:60-69`), so the next successful sync would adopt the server document and silently drop the user's local edits. Rejected: build a user-facing surface now — that is the P1 "surface pending/failed/quarantined intents" item; this plan only guarantees no data loss and no futile network write.

**D8 — The KDF guard lives inside `deriveRootKey`.**
Chosen: one `assertKdfParams(saltBytes.length, iterations)` at the top of `deriveRootKey` (`packages/vault-core/src/crypto.ts:78-107`). Every web, extension and import path funnels through it (`createAuthKey`, `derivePasswordWrappingKey`, both at `:311-334`), so there is exactly one choke point and no call site can forget.
Rejected: assert at each call site — there are five (`flows.ts:35`, `utils.ts:53`, `login.ts:30`, `import.ts:126`, `extension/background/vault.ts:513`), which is how drift starts. Rejected: reject out-of-range rows in `/auth` and `/get_crypto_params` — it creates a new existence/version oracle after a successful verifier, and it cannot help the import path, which never touches those endpoints. Reads describe, writes refuse, derivation asserts.

**D9 — Recovery selector shape failures stay on the uniform 401.**
Chosen: a non-canonical selector short-circuits to `auth_failed()` before the query.
Rejected: return 400 like `rewrap` does for a malformed proof — it would break the "every proof-path failure is byte-identical" invariant that `unlock_failures_are_byte_identical` pins, and that invariant is the anti-oracle property of the whole recovery design.

**D10 — Session before shape.**
Chosen: see §3.5. Rejected: shape first — a 400 on a session-less request leaves the client's `serverSession` marked `active` and suppresses the teardown that should run on 401 (`http.ts:47-56`).

**D11 — No new logging on rejection.**
Chosen: validation failures return the envelope and log nothing; expected client mistakes must not become a log-spam vector, and the log-sanitisation P0 is open. The only new log line is the client-side `VAULT_TOO_LARGE` (size and cap only). Never log a field value, ciphertext, verifier, or request body.

---

## 5. Files to touch

### New

| File | Purpose |
|---|---|
| `apps/server/src/endpoints/validate.rs` | Constants, `FieldError`, base64/UUID/KDF primitives, unit tests. Declared in `endpoints/mod.rs`; `json_config()` gains `.limit(MAX_JSON_BODY_BYTES)`. |
| `packages/vault-core/src/bounds.ts` | `MAX_VAULT_CIPHERTEXT_BYTES`, `KDF_READ_FLOOR`, `parseBase64Exact`, `parseBase64Bounded`, `assertKdfParams`, `assertVaultCiphertextSize`. |
| `packages/vault-core/test/bounds.test.ts` | Table tests mirroring the Rust vectors, including URL-safe/unpadded/trailing-bit/whitespace rejects. |
| `docs/request-bounds.md` | The human-readable contract: the constant table, the per-endpoint matrices from §3.3, and the base64 char-length cheat sheet (16 B → 24 chars, 12 B → 16, 32 B → 44, 48 B → 64). |

### Edit

| File | Change |
|---|---|
| `apps/server/src/endpoints/mod.rs` | `pub mod validate;`; `.limit(validate::MAX_JSON_BODY_BYTES)`; keep the 413 mapping. |
| `apps/server/src/endpoints/register.rs` | `RegisterRequest` shape; required `crypto_version`; `validate_register()`; use `crate::error::error_response` (delete the private copy); update placeholder fixtures to exact lengths. |
| `apps/server/src/endpoints/vaults.rs` | Required verifier, no `unwrap_or_default`; required `crypto_version`; validate before the existence `SELECT`; new test module. |
| `apps/server/src/endpoints/auth.rs` | `validate_auth()`; trimmed comparison; delete the private error helper. |
| `apps/server/src/endpoints/update_vault.rs` | Request becomes 3 fields + `deny_unknown_fields`; version bounds + `checked_add`; non-v2 guard; update statement no longer touches envelope columns; `iterations` response type `u32` → `i32`; add `json_config()` to the test app; update fixtures. |
| `apps/server/src/endpoints/update_vault_password.rs` | Verifier shape; 409 for `new_salt`/`new_iterations`; tests. |
| `apps/server/src/endpoints/recovery.rs` | Delete `decode_exact`, `canonical_uuid` and the length/KDF constants; import from `validate`; selector pre-check on unlock/rewrap/regenerate; new selector tests. No change to proof semantics or column discipline. |
| `apps/server/src/endpoints/cloud_endpoints.rs` | Package cap on create/replace; canonical `vault_id`; `MAX_REMOTE_ID_LEN` on file ids/revisions; fixtures. |
| `apps/server/src/error.rs` | No shape change; it becomes the single `error_response` implementation. Note: tests stay in each endpoint's existing `#[cfg(test)] mod tests`, not a new module. |
| `packages/vault-core/src/crypto.ts` | One `assertKdfParams` call at the top of `deriveRootKey` (`:78`). No crypto change. |
| `packages/vault-core/src/index.ts` | Re-export `bounds.ts`. |
| `packages/vault-core/src/schema.ts` | `UpdateVaultRequest` loses `crypto_version`, `vault_key_wrap`, `vault_key_wrap_iv` (`:570-577`). |
| `apps/client/src/lib/sync/index.ts` | Size pre-check after `encrypt()` (`:160-168`). |
| `apps/client/src/lib/vault/import.ts` | Validate every package field's shape before `derivePasswordWrappingKey` (`:105-127`); replace the `!iterations` truthiness check. |
| `apps/extension/src/background/vault.ts` | Size pre-check before `postUpdateVault` (`:1415-1421`). |
| `apps/client/src/lib/queries/vaults/query.ts` | `CreateVaultRequest`: `vault_verifier` and `crypto_version` become required (matches the server; no caller today). |
| `AGENTS.md` | One Gotcha line: every write boundary validates through `endpoints/validate.rs`, mirrored by `vault-core/bounds.ts`; do not add a literal elsewhere. |
| `SECURITY_AND_FEATURE_ROADMAP.md` | Tick the item and correct the "no body limit" wording once implemented. |

### Do not touch

| Area | Why |
|---|---|
| `apps/server/migration/**` | No schema change. SQLite has no length constraint that would not require a table rebuild, and a `CHECK` would reject existing dev rows. |
| `apps/server/src/entity/vault.rs` | Column types already fit (`iterations: i32`, `crypto_version: i32`, `String` blobs, `entity/vault.rs:10-22`). |
| `apps/server/src/session_auth.rs`, `lock.rs`, `logout.rs`, `pair.rs`, `favicon.rs`, `get_vault.rs`, `get_crypto_params.rs` | Read/session paths; untouched by this item (except the shared error helper, which is additive). |
| `apps/server/src/cloud/package.rs` | Package format stays byte-compatible (`PACKAGE_FORMAT_VERSION = 2`, `:32`); only its *input* size is bounded. |
| `apps/server/src/cloud/mirror.rs` | It re-serialises whatever the row holds; the caps upstream are what bound it. |
| `packages/vault-core/src/crypto.ts` KDF **values** | `ITERATIONS = 60000` is the other P0's to move; this plan adds only the `assertKdfParams` call and changes no constant there. |
| `apps/client/src/lib/crypto/*` | No crypto change. |
| Cloud credential/token storage (`cloud_token`, `cloud_pending_token`) | P1 "encrypt persisted cloud credentials"; unrelated. |

---

## 6. Trust boundary

### Must not break

- **Zero knowledge.** No new field carries a password, vault key, or plaintext. Validation inspects only length and decodability of opaque blobs; it never decodes-to-inspect, never compares ciphertext, and never logs a value. The server still sees exactly: salt, iterations, `vault_verifier`, `recovery_verifier`, the ciphertext IV, and the two envelopes.
- **Rule R1.** The recovery envelope still wraps `vaultKeyRaw` directly (`crypto.ts:476-503`, `entity/vault.rs:43-47`). Nothing in this plan changes what is wrapped; the rewrap column discipline (`recovery.rs:736-745`) is untouched.
- **Session semantics.** The vault id on every write stays session-derived; body ids remain consistency checks only. Error ordering keeps `401 SESSION_REQUIRED` first so the client's teardown path still fires (§3.5).
- **Per-vault namespacing.** No storage key, OPFS filename, or IndexedDB record name changes; no cross-vault query is added.
- **Recovery's uniform failure.** The one-identical-401 rule survives (D9); the existing test must pass unchanged except for the new selector case.
- **COOP/COEP and `no-store`.** `main.rs:300-318` is untouched. `validate.rs` adds no headers.
- **CAS semantics.** `/update_vault` still writes only when `version` matches, and the response still reports `version + 1`. Removing the envelope columns from the update statement cannot affect conflict behaviour.

### New attack surface introduced

- **Precise error messages** enumerate the expected shape (e.g. "must be 48 bytes of base64"). This is public protocol, not a secret, and it removes a class of un-debuggable failures. Accepted.
- **A larger body cap (2 → 12 MiB)** raises peak memory per concurrent request. The server binds loopback by default (`main.rs:365`) and the field caps bound stored bytes, but a request flood is still possible — that is the rate-limiting P0.
- **A larger per-request ciphertext cap (≈1.5 → 4 MiB)** raises the cost of an unauthenticated `/register` flood per request (D5). Request *count* is unbounded either way.
- **`deny_unknown_fields`** makes field names enumerable — same as any request schema. Accepted.

### Residue this item does not close

- Request floods on `/auth`, `/register`, `/get_crypto_params` (rate-limiting P0).
- Replay of a stolen `vault_verifier` and its non-constant-time comparison (verifier P0).
- A hostile *server* can still supply a huge iteration count; the client's `assertKdfParams` converts that into a clear refusal rather than a hang, which is the best a client can do.
- Unbounded *individual* item fields (`site`, `username`, `password` have no `.max()`, `schema.ts:108-147`). The document cap is the enforcement point; per-field limits are UX and would need UI copy plus an import story. Deliberate non-goal.

---

## 7. Phases

Each phase leaves the tree working. Run `cargo test` (in `apps/server`), `npm test` (in `packages/vault-core`), and `npx tsc --noEmit` (in `apps/client` and `apps/extension`) at the end of each.

### M0 — Contract and foundations (only narrowing: ids must be v4)

**Scope**
1. Add `apps/server/src/endpoints/validate.rs`: constants, `FieldError`, `canonical_uuid`, `b64_exact`, `b64_bounded`, `kdf_ok`, `crypto_version_ok`, and the field-name wrappers. Unit tests for every primitive.
2. `endpoints/mod.rs`: `pub mod validate;` and `.limit(validate::MAX_JSON_BODY_BYTES)`. This strictly *raises* the limit from 2 MiB to 12 MiB, so nothing that worked stops working.
3. Move `decode_exact`, `canonical_uuid`, `SALT_LEN`, `IV_LEN`, `WRAP_LEN`, `VERIFIER_LEN`, `PROOF_LEN`, `CHALLENGE_LEN`, `MIN_NEW_ITERATIONS`, `MAX_NEW_ITERATIONS` out of `recovery.rs` into `validate.rs`. Recovery imports them; the only intentional narrowing is that ids must now be **v4** (all producers are).
4. Consolidate `error_response`: delete the private copies in `register.rs`, `auth.rs`, `update_vault.rs`; use `crate::error::error_response`.
5. Add `packages/vault-core/src/bounds.ts` + export; call `assertKdfParams` at the top of `deriveRootKey`.
6. Add `docs/request-bounds.md` (the §3 tables and the char-length cheat sheet).
7. Tests: `validate.rs` unit table; vault-core `bounds.test.ts`; an HTTP test that a 12 MiB + 1 byte body returns 413 `PAYLOAD_TOO_LARGE` with the JSON envelope, and a 12 MiB body just under it reaches the handler.

**Acceptance**
- `cargo test` green, including the full recovery suite and `unlock_failures_are_byte_identical`.
- `npm test` in `packages/vault-core` green, including a case where `derivePasswordWrappingKey(pw, salt, 1)` rejects in well under a second instead of deriving.
- `curl` a 13 MB body at `/api/auth` → `413 {"code":"PAYLOAD_TOO_LARGE"}`.
- `npx tsc --noEmit` in both apps.

### M1 — Creation boundaries (`/register`, `/vaults`)

**Scope**
1. `validate_register` / `validate_create_vault` per §3.3; `crypto_version` required and `== 2`; `/vaults` requires `vault_verifier`.
2. Validation before the first DB access in both handlers (move the existence `SELECT` in `vaults.rs:69-77` after validation).
3. Update every HTTP fixture that still uses placeholder lengths: `register.rs` tests (`valid_body`, `:312-328`), `update_vault.rs` `authenticated_app!` (`:252-292`), `cloud_endpoints.rs` `authenticated_app!` (`:1695-1716`), `recovery.rs` `seed_with_session!` (`:2039-2071`). Seed rows inserted directly with `ActiveModel` stay as they are — they bypass the handler on purpose.
4. Table tests: for each field, one mutation → `400 INVALID_INPUT`, **no row**, **no session cookie**; plus a 4 MiB ciphertext accepted and 4 MiB + 1 rejected.

**Acceptance (hand)**
- Web signup creates a vault; the DB row decodes to the expected lengths:
  `sqlite3 ~/Library/Application\ Support/Voult/voult.db "select length(salt), length(vaultiv), length(vault_verifier), length(vault_key_wrap), length(vault_key_wrap_iv), length(recovery_verifier), length(recovery_salt), length(recovery_wrap), length(recovery_wrap_iv), crypto_version, iterations from vault"` → `24|16|44|64|16|44|24|64|16|2|60000` for a fresh vault.
- Drive restore still registers a vault (`importVaultFromCloud` path).
- `curl` `/api/register` with `iterations: 59999` → 400, and `select count(*) from vault where id='<id>'` → 0.
- `curl` `/api/register` with `crypto_version` omitted → 400 (serde's message via `json_config`).
- `curl` `/api/register` with `vault_verifier: "a"` → 400; the same value through `/api/auth` → 400 (not 401).

### M2 — Auth, document writes, password metadata

**Scope**
1. `validate_auth`; trimmed comparison.
2. `UpdateVaultRequest` → `{ vault, vaultiv, version }` + `deny_unknown_fields`; version range; `checked_add`; non-v2 guard; update statement writes only the three columns.
3. `UpdateVaultResponse.iterations` → `i32` (Rust) and the same field stays `number` (TS). Update `packages/vault-core/src/schema.ts:570-577`.
4. `/vault/password` per §3.3 (409 for salt/iterations).
5. Add `json_config()` to the `update_vault` test app (it currently uses the default config, so unknown-field and overflow behaviour is untested).
6. Tests: auth shape + uniform 401; update_vault field table (`version: 0`, `version: 2147483647`, `version: 4294967295`, non-base64 iv, 4 MiB + 1, obsolete envelope field → 400, non-v2 row → 409, stale version → 409 unchanged); password endpoint table.

**Acceptance (hand)**
- Web login works with a 32-byte verifier; a wrong verifier still returns `401 AUTH_FAILED` with the same body as an unknown vault (compare with `curl -i`).
- Web sync of a new item succeeds and the version increments by 1.
- Extension "save login" still succeeds (it sends exactly the three fields, `background/vault.ts:1418-1421`).
- `curl /api/update_vault` with `"crypto_version": 1` → 400 mentioning `unknown field`; with `"version": 0` → 400; with a stale version → 409 `VERSION_CONFLICT` and the stored document unchanged.
- `curl /api/vault/password` with `new_salt` present → 409 `PASSWORD_CHANGE_REQUIRES_REWRAP`; the row is byte-identical.

### M3 — Size caps and client mirrors

**Scope**
1. Server: `MAX_CIPHERTEXT_LEN` on register/vaults/update_vault; `MAX_PACKAGE_LEN` + encoded-length pre-check on cloud create/replace; `MAX_REMOTE_ID_LEN` on cloud identifiers.
2. Client: size pre-check in `sync/index.ts` and the extension; import validates every field's exact shape and the ciphertext cap **before** line 126.
3. Tests: 4 MiB accepted / 4 MiB + 1 rejected at `/update_vault`; 6 MiB + 1 package rejected; cross-constant invariants (`base64_len(MAX_CIPHERTEXT_LEN) < MAX_PACKAGE_LEN < base64-adjust(MAX_JSON_BODY_BYTES)`).
4. `docs/request-bounds.md` updated if any number moved.

**Acceptance (hand)**
- `python3` generates 4,194,304 random bytes, base64-encodes them, posts to `/api/update_vault` with the current version → 200; +1 byte → 400 `INVALID_INPUT`, version unchanged, document unchanged.
- Paste a ~4.2 M-character value into one item's password field (the only unbounded field reachable from the UI), press sync → the client logs `vault ciphertext … exceeds …` once, no network write; in the dev console `fetchPendingIntents()` still returns the rows (i.e. they were not marked errored), and the server's `version` column is unchanged.
- Hand-edit a downloaded package's `cryptoParameters.iterations` to `2147483647` and import it: the import fails in well under a second with a KDF-params message, with no PBKDF2 spin and no `/register` request in the network log.
- "Back up now" still succeeds for a normal vault (the package path is unchanged).

### M4 — Hardening and verification

**Scope**
1. Verify the `deny_unknown_fields` serde path produces the documented 400 with `json_config` installed (added in M2), and that every endpoint in §3.3 has at least one shape test — walk the table row by row.
2. Log review: grep the diff for any new log line containing a field value; confirm none.
3. Update `AGENTS.md` (one Gotcha line) and tick the roadmap item with a corrected description.
4. Run the full manual matrix in §8.

**Acceptance**
- `cargo test` (all suites), `npm test` in `packages/vault-core`, `npx tsc --noEmit` in both apps, `npm run build:web` in `apps/client`.
- The manual matrix below.

---

## 8. Test matrix

| # | Case | Expected |
|---|---|---|
| 1 | `/register` with each of the 13 fields mutated to an invalid shape | 400 `INVALID_INPUT`, no row, no cookie, one test per field |
| 2 | `/register` with `crypto_version` omitted / `1` / `3` | 400 |
| 3 | `/register` with `vault` at exactly 4 MiB | 201 |
| 4 | `/register` with `vault` at 4 MiB + 1 | 400, no row |
| 5 | `/vaults` with `vault_verifier` omitted | 400 (and never an empty string in the row) |
| 6 | `/auth` with a 1-byte verifier | 400 (not 401) |
| 7 | `/auth` with a well-formed wrong verifier | 401 `AUTH_FAILED`, byte-identical to an unknown vault |
| 8 | `/update_vault` with `vault_key_wrap` present | 400 (unknown field) |
| 9 | `/update_vault` with `version: 0` / `2147483647` / `4294967295` | 400 |
| 10 | `/update_vault` with a non-v2 row | 409 `UNSUPPORTED_CRYPTO_VERSION`, row unchanged |
| 11 | `/update_vault` with a stale version | 409 `VERSION_CONFLICT`, row unchanged |
| 12 | `/vault/password` with `new_salt` or `new_iterations` | 409, row byte-identical |
| 13 | `/recovery/unlock` with a non-UUID selector | 401 whose body equals the wrong-proof body |
| 14 | `/recovery/rewrap` with each field wrong length | 400, vault byte-identical, challenge still live |
| 15 | Body of 12 MiB + 1 | 413 `PAYLOAD_TOO_LARGE` |
| 16 | Cloud create/replace package decoded > 6 MiB | 400 (package size), provider not called |
| 17 | `derivePasswordWrappingKey(pw, salt, 1)` and `(…, 2_000_001)` | throws before any PBKDF2 work |
| 18 | Sync with a > 4 MiB document | no network write, intents still pending |
| 19 | Import a package with a bad envelope length / wrong crypto version | clear error before KDF |
| 20 | Full happy paths: signup, login, item add + sync, extension save, `/recover`, "Back up now" | unchanged |

---

## 9. Overlaps with other roadmap items (do not fix here)

| Item | Seam |
|---|---|
| **P0 — Rate-limit authentication and pre-auth endpoints** | Bounds reduce the cost of one request; they do not bound request count. `/register` can still be flooded, now with up to 4 MiB per request. |
| **P0 — Remove the reusable verifier as a replayable credential** | This plan makes the verifier exactly 32 bytes but leaves `!=` comparison and the replayable protocol untouched (`auth.rs:99`). |
| **P0 — Strengthen password KDF and add a migration profile** | Owns `KDF_ITERATIONS_MIN/MAX` and `PBKDF2_ITERATIONS`. The seam is `validate.rs` + `bounds.ts` (§3.6). If the KDF stops being PBKDF2, that item owns the wire/column change. |
| **P0 — Sanitize HTTP/access logs** | This plan adds no per-request logging (D11); the request-line format is theirs. |
| **P1 — Complete password-change protocol atomically** | Owns the rewrap request shape (new envelope + `credential_version` CAS) that will replace the restricted `/vault/password` body. |
| **P1 — Surface pending/failed/quarantined intents** | Owns the UI that explains `VAULT_TOO_LARGE` to the user. This plan only guarantees no data loss. |
| **P0 — Security-focused automated tests** | The per-field tables here are a down payment on "input-limit" coverage; that item owns the broader gate. |

---

## 10. Deliberate non-goals

- **No rate limiting, CSRF/origin checks, or session changes.**
- **No crypto changes**: no AAD for the password/device envelopes (P2), no KDF change, no nonce-reuse detection (impossible server-side).
- **No schema/migration**: the caps live in code; SQLite column types already fit.
- **No per-item sync**: the single-blob document stays. 4 MiB is a ceiling, not a design.
- **No per-field item limits** (`site`/`username`/`password`): the document cap is the enforcement point; per-field limits need UI copy and an import story.
- **No new dependencies.**
- **No backward-compatibility shims**: there are no releases. Removing `crypto_version`/envelope fields from `/update_vault` and dropping v1 support are in-place changes, and the only writers are the web app and the extension, both updated in the same tree.

---

## 11. As-built notes (2026-10-29)

The implementation followed M0–M4. Names and small choices that differ from the
text above, recorded so the next reader does not have to diff:

- **`endpoints/validate.rs` API.** Primitives are `decode_exact(s, len)`,
  `b64_length_in(s, min, max)`, `canonical_uuid(raw) -> Option<Uuid>`,
  `canonical_uuid_string(raw) -> Option<String>`, `kdf_ok`, `crypto_version_ok`.
  Field wrappers are `require_uuid`, `require_b64_exact`,
  `require_b64_in_range`, `require_kdf`, `require_crypto_version`,
  `require_remote_id`. `FieldError.expected` is a `String` so the bounded-field
  messages can embed the numbers.
- **One shared creation validator.** `VaultMaterial` +
  `validate_vault_material` hold the twelve crypto-field rules; `/register` and
  `/vaults` both call them, so the two cannot drift again.
- **Base64 canonicality is hand-rolled** in both languages (alphabet, multiple
  of 4, padding at the end only, zero trailing bits). The Rust unit test pins it
  against the `base64` engine's `STANDARD` behaviour; the TS test pins explicit
  vectors. Rejected `btoa(atob(s))` because the 4 MiB ciphertext would overflow
  the stack when spread into `String.fromCharCode`.
- **`vault` validation does not decode.** `b64_length_in` computes the decoded
  length from the canonical string, so a 5.6 MB body does not allocate a second
  4 MiB buffer just to be rejected/accepted.
- **`UpdateVaultResponse.iterations`** changed from `u32` to `i32`; the JSON
  number is unchanged for every valid row.
- **Client import** validates the package's crypto version, salt, IVs, both
  envelopes, and the ciphertext length before `derivePasswordWrappingKey`.
  `assertKdfParams` also lives inside `deriveRootKey`, so every path is covered
  even if a future caller forgets the package-level checks.
- **Client size checks**: web sync logs one error and returns with intents still
  pending (`synced = 0, error IS NULL`); the extension throws a readable error so
  the pending save is not silently dropped.
- **Cloud writes**: `decode_package` checks the encoded length before decoding
  and the decoded length before parsing; `file_id` / `remote_revision` /
  `if_match_revision` are capped with `require_remote_id`.
- **Verification.** `cargo test` 121/121 (new: validate primitives, body limit,
  per-field registration table, max-size ciphertext, auth shape/uniformity,
  update_vault malformed table, non-v2 refusal, password rotation, `/vaults`
  verifier/crypto-version, package cap, recovery selector uniformity);
  `packages/vault-core` 130 tests (125 pass, 5 skipped for missing
  poppler/ghostscript); client and extension `npx tsc --noEmit` pass;
  `npm run build:web` exports cleanly.
- **Not verified here:** the browser flows (signup, login, item sync, extension
  save, recovery UI) were not exercised against a live server in this worktree.
  The server-side checks and the manual curl matrix (register/low-iterations/
  short verifier/oversized ciphertext, auth shape, update_vault obsolete field
  and version 0, password 409, body 413, recovery challenge + uniform 401,
  row-length inspection) were run against a scratch SQLite database and passed.
