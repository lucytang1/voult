# P0 — Argon2id password KDF with a versioned profile and client-side rewrap

**Status:** implemented on `p0/kdf-profile` (2026-10-28)
**Revision:** 2 — no legacy handling (see the note below)
**Branch:** `p0/kdf-profile`
**Roadmap item:** `SECURITY_AND_FEATURE_ROADMAP.md:56` — "Strengthen password KDF and add a migration profile"
**Scope owner:** password-key derivation only. Not the verifier protocol, not password change UX, not envelope AAD.

> **Revision 2.** There are no released vaults and no released backup packages, so this plan
> carries **no legacy path at all**: PBKDF2 is deleted from the codebase rather than kept for
> old credentials, the schema change has no backfill, and the package reader accepts only the
> new format. Existing development databases are deleted instead of migrated — the repo
> already uses that clean-start model (`apps/server/migration/src/lib.rs:4-7`). The client-side
> rewrap machinery remains, because it is what upgrades a vault between profile rungs (and
> what every future KDF change will use), not because anything needs rescuing today.

---

## 0. Summary

Every vault's password credential is derived with **PBKDF2-HMAC-SHA256 at 60,000
iterations** (`packages/vault-core/src/crypto.ts:12`) and the iteration count is a bare
integer shared by the wire, the database and the backup package. There is no profile
identity, no floor, no upgrade path, and no way for a client to tell a strong vault from a
weak one except by reading that integer.

This plan replaces that with:

1. **Argon2id** (RFC 9106) as the only password root KDF, implemented by a pinned,
   zero-dependency pure-JS library (`@noble/hashes@2.4.0`), with the existing HKDF `auth` /
   `vault-wrap-v2` split kept byte-identical. PBKDF2 is removed from `vault-core`, the
   server, the web app and the extension.
2. A **self-describing KDF descriptor** carried on the wire, at rest, and inside cloud
   packages: `{ algorithm, memory_kib, time_cost, parallelism }`. The descriptor *is* the
   version; adding a rung never reinterprets an old row.
3. A **device-calibrated profile ladder** (19 / 32 / 64 MiB, `p=1`) with a hard OWASP floor.
4. **Client-side rewrap** as the only way a credential changes — the password and vault key
   never leave the device. The server sees a new salt, a new descriptor, a new verifier and a
   new ciphertext envelope, all of which it already stores today.
5. A **single atomic credential-rotation endpoint** (`POST /api/vault/credential`) that
   replaces the broken `/vault/password` (`apps/server/src/endpoints/update_vault_password.rs`),
   guarded by a verifier reauthentication proof, a `credential_version` compare-and-swap, and
   a no-downgrade rule.

The recovery envelope is untouched: it wraps `vaultKeyRaw` directly (Rule R1,
`packages/vault-core/src/crypto.ts:536`), so a password-KDF change cannot orphan it. A
recovery rewrap simply installs the new profile as a side effect.

---

## 1. The issue, stated plainly

Today, an attacker who obtains a vault's stored material — the database file, a Drive
package, or a leaked backup — holds `salt`, `iterations`, `vault_verifier`, and the
password-wrapped vault key. They do not need the server: each password guess is
`PBKDF2(password, salt, 60_000) → HKDF → HMAC`, compared against the verifier, or the same
root used to unwrap the envelope. On this machine that is **7 ms per guess**
(`crypto.subtle.deriveBits`, measured; §2.3). A single GPU runs thousands of those in
parallel, so a human-memorable password (roughly 35–45 bits) is reachable in hours to
months, and a weak or reused password in minutes. The vault key, and therefore every
password in the vault, falls with it. The precondition is not exotic: it is any read of the
SQLite file, any downloaded backup, any stolen laptop.

"Fixed" means three things at once: new credentials are memory-hard and calibrated above a
published floor; each stored credential says exactly which profile it used; and a vault can
move to a stronger profile through a local rewrap, with a server write that is atomic,
authorised, and never a downgrade. Because there is no existing population, every vault is
born on Argon2id — there is no set of old credentials to rescue, and no "user never returns"
legacy exposure. A vault that is never unlocked again simply stays on the rung it was created
with, which is already at or above the floor (§5.5).

---

## 2. Research findings

### 2.1 What the code actually does

- Root derivation: PBKDF2-HMAC-SHA256, 256 bits, salt from `newSaltB64()` (16 random
  bytes), iteration count a module constant of 60,000 (`packages/vault-core/src/crypto.ts:12`,
  `:34-43`, `:78-107`).
- Two child keys via HKDF-SHA256 with distinct labels: `auth` and `vault-wrap-v2`
  (`crypto.ts:20-24`, `:311-334`). `vault_verifier = HMAC-SHA256(authKey, "auth-v1|static")`
  (`crypto.ts:185-194`).
- Password envelope: AES-GCM over `vaultKeyRaw` under the wrap key, **no AAD**
  (`crypto.ts:256-277`; the AAD gap is a separate P2, §9).
- The server stores and serves `salt` + `iterations` unauthenticated
  (`apps/server/src/endpoints/get_crypto_params.rs:16-37`, `:92-100`) and duplicates them in
  `/auth` (`auth.rs:27`, `:136-137`), `/get_vault` (`get_vault.rs:22`, `:86`) and
  `/update_vault` (`update_vault.rs:31`, `:168`).
- Registration accepts any `i32` iteration count (`register.rs:22`, `:146`) and defaults
  `crypto_version` to **1** when the field is absent (`register.rs:125`); `/vaults` defaults to
  2 instead (`vaults.rs:127`).
- Recovery rewrap already performs the exact write shape a KDF rotation needs — new salt,
  new iteration count, new verifier, new envelope — with a `credential_version` CAS
  (`apps/server/src/endpoints/recovery.rs:720-733`, `:850-887`, `:786-791`). Its iteration
  bounds are hard-coded at 60k–2M (`recovery.rs:68-73`).
- `/vault/password` (`update_vault_password.rs`) accepts a verifier plus optional salt and
  iterations and writes them **without** a new envelope and **without** CAS (`:54-61`). It is
  exactly the "strand the vault" bug the roadmap describes, and it has no client.
- The backup package carries `cryptoParameters: { salt, iterations }`
  (`apps/server/src/cloud/package.rs:44-48`, `:167-170`) and pins `PACKAGE_FORMAT_VERSION = 2`
  (`package.rs:32`). The client reader consumes `cryptoParameters.iterations`
  (`apps/client/src/lib/vault/import.ts:105-107`, `:126`, `:168`). The server is the only
  package producer; the client's `createVoultPackage` (`apps/client/src/lib/crypto/vault.ts:155`)
  has no caller.
- Every derive site passes the raw iteration integer: web (`flows.ts:35-40`, `:229`;
  `lock.ts:107`; `signup.ts:63`, `:89`; `open.ts:18`; `import.ts:126`), recovery
  (`recover.ts:205-240`), extension (`apps/extension/src/background/vault.ts:513-516`,
  `api.ts:37-42`).
- `LockMetadata` also pins the shape (`packages/vault-core/src/schema.ts:435-440`).
- No shared-core test derives a password. `packages/vault-core/test/crypto-recovery.test.ts`
  pins the recovery HMAC labels only, so deleting PBKDF2 has no test fallout there; the
  server tests are the ones that construct `iterations` fixtures (§7).

### 2.2 Is the roadmap claim still accurate?

Yes. One part is understated, and one phrase needs a qualifier:

- **Still accurate:** there is no profile identity, no floor and no upgrade path. 60,000 is
  the live value in the shared core, the web app and the extension.
- **Understated:** the same integer is accepted with no bounds (`register.rs:146` is
  unauthenticated; `vaults.rs:132` is session-scoped), so a client bug or a hostile caller
  can create a vault at `iterations: 1`. This plan's validation closes that for the fields it
  owns; `/auth` and `/update_vault` remain with the separate bounds P0 (§9).
- **Qualified:** "migrate by client-side rewrapping" is the only possible mechanism because
  the server never has the password or the vault key. It is also **not needed for any
  currently existing vault**, since none are released. The plan therefore ships the rewrap
  mechanism (for future rung upgrades) and no compatibility data path at all. That is the
  AGENTS.md default: no releases means change schemas and wire contracts in place.

### 2.3 Measured cost (this machine, Node v24.19.0, Apple silicon)

| Derivation | Time |
|---|---|
| PBKDF2-SHA256, 60,000 — **the code being removed** | **7 ms** |
| PBKDF2-SHA256, 600,000 — for comparison | 87 ms |
| Argon2id m=19,456 KiB, t=2, p=1 — native (`node:crypto.argon2`) | 25 ms |
| Argon2id m=65,536 KiB, t=3, p=1 — native | 161 ms |
| Argon2id m=19,456 KiB, t=2, p=1 — `@noble/hashes` | 121 ms |
| Argon2id m=32,768 KiB, t=3, p=1 — `@noble/hashes` | 298 ms |
| Argon2id m=65,536 KiB, t=3, p=1 — `@noble/hashes` | **590 ms** |

Two things follow. First, the attacker's cost is set by the parameters, not by our
implementation: an attacker runs native/GPU code, so our 590 ms JS figure is an honest-client
cost only. Second, the honest-client cost is what the ladder exists to bound — 590 ms here
becomes roughly 2.5–3.5 s on a low-end phone, which is why calibration may step down.

`@noble/hashes` is ~3.7× slower than native (590 vs 161 ms), matching its own documented
"5× slower than native" warning. That tax is acceptable because it buys memory hardness
without WASM.

### 2.4 What the standards say (checked, not assumed)

- OWASP Password Storage Cheat Sheet: Argon2id minimum **m=19,456 KiB, t=2, p=1** (equal
  alternatives: 46 MiB/t=1, 12 MiB/t=3, 9 MiB/t=4, 7 MiB/t=5); PBKDF2-HMAC-SHA256 600,000 is
  the FIPS-140 fallback — irrelevant here, because there is no FIPS constraint and no legacy
  credential.
- RFC 9106 recommends 64 MiB/t=3/p=4 (low-memory profile) or 2 GiB/t=1/p=4 (high-memory).
  `p` is the number of lanes, not a cost multiplier; for a single-threaded browser client
  `p=1` is correct and avoids giving the attacker a parallel lane for free.
- WebCrypto has no Argon2 and no scrypt. There is no native browser option.

---

## 3. Decisions (settled; each carries its rationale)

### D1 — Argon2id, pure JS, via `@noble/hashes@2.4.0` (pinned, no caret)

**Chosen.** Zero transitive dependencies, audited (MIT), ESM, works unchanged in the Expo web
bundle, the MV3 service worker and Node tests. The call is
`argon2id(utf8(password), saltBytes, { m: memory_kib, t: time_cost, p: parallelism, dkLen: 32 })`
from `@noble/hashes/argon2.js`. Memory-hard, so an offline attacker's parallelism is capped by
memory bandwidth rather than by SHA-256 throughput.

**Rejected — calibrated PBKDF2 at 600k–1.2M.** Ten to twenty times today's cost, no new
dependency, one-line change. Rejected because it remains a compute-only function: a GPU or
ASIC scales it cheaply, and the defender's own latency (139 ms at 1.2M here, over a second on
a phone) buys less attacker cost per millisecond than 64 MiB of Argon2 does. It is a
stopgap, not a fix.

**Rejected — scrypt.** Memory-hard and acceptable per OWASP, but no WebCrypto support
either, so it needs the same kind of dependency, and Argon2id is the current recommendation
with no advantage lost by choosing it.

**Rejected — Argon2id via WASM (`hash-wasm`, `libsodium.js`, vendored `argon2`).** Fastest
(≈160 ms native-equivalent), but it requires `'wasm-unsafe-eval'` in the MV3
`extension_pages` CSP (`apps/extension/src/manifest.json:34-35`, currently
`script-src 'self'; object-src 'self'`), plus WASM asset plumbing in both the Expo export and
the Vite extension build. Weakening the extension's script policy and adding a build step to
save ~400 ms on a rare unlock is a bad trade. Revisit only if measured real-device unlock
latency breaches the budget after the ladder bottoms out.

**Rejected — hand-rolled Argon2 or a "PBKDF2 + own memory-hard mix".** Never implement a KDF
yourself. Non-negotiable.

**Dependency justification (required by AGENTS.md).** Argon2 has no WebCrypto API; the
alternative to a dependency is either a weak KDF or an unauditable implementation. The
library is pinned exactly, audited, dependency-free, and gated by known-answer tests against
an independent implementation (§10.2). It is added to `packages/vault-core` only, so there is
one implementation for web, extension and tests.

### D2 — The profile is a structured descriptor, not an integer and not an opaque id

```ts
type KdfParams = {
  algorithm: "argon2id";
  memory_kib: number;
  time_cost: number;
  parallelism: number;
};
```

Self-describing for packages, unambiguous in logs, and directly derivable by both languages.
The descriptor is matched **exactly** against an append-only registry in `vault-core` and a
mirrored allowlist in the server; a tuple that is not on the ladder is rejected, not
interpreted. There is deliberately no legacy variant and no free-form range: PBKDF2 is not a
supported algorithm anywhere in the new codebase. This is what "separately versioned profile"
means here: every rung is a distinct, immutable identity, and adding a rung cannot change how
an old row is read. Adding a rung is a server-first deploy; an old server rejects it with
`KDF_UNKNOWN`, which is the correct fail-closed behaviour.

*Rejected:* a bare `kdf_profile: "argon2id-64m-t3"` string (compact but hides the actual
parameters from the one party — the server — that must validate them, and invites string
parsing in two languages). *Rejected:* free-form bounded integers (allows `m=19457` nonsense
and gives calibration no closed set to choose from). *Rejected:* a `version: 1` field (the
descriptor already determines the output; a version integer with nothing to version is a
lie).

### D3 — Ladder: three Argon2id rungs, `p=1`, 16-byte salt, 32-byte output

| Rank | Profile | Params | Measured here (`@noble/hashes`) |
|---|---|---|---|
| 3 (top) | `argon2id-64` | m=65,536 KiB, t=3, p=1 | 590 ms |
| 2 | `argon2id-32` | m=32,768 KiB, t=3, p=1 | 298 ms |
| 1 (floor) | `argon2id-19` | m=19,456 KiB, t=2, p=1 | 121 ms |

The floor is the OWASP minimum and is never crossed, even if a device cannot meet the latency
budget. The top is RFC 9106's 64 MiB shape with `p` reduced from 4 to 1 for a single-threaded
client. Salt stays 16 bytes (RFC's 128-bit recommendation), output stays 32 bytes, and the
password is encoded as UTF-8 exactly as today. There is no lower rung to fall back to and no
legacy algorithm to keep alive.

### D4 — Calibration is device-local, web-only, and choose-the-highest-under-budget

`calibrateKdf({ budgetMs: 700 })` runs each rung once on random input (never on the user's
password) and returns the highest rung that completes within budget, never below the floor.
It is cached in `localStorage` under `voult.kdfTarget.v1` together with
`KDF_LADDER_VERSION`. It runs at signup and lazily before a first upgrade — **not** on every
unlock. The extension never calibrates and never rotates; it derives with the vault's stored
profile (§5.6). Rationale: calibration is a property of the device that creates or upgrades
the credential, not of every device that opens it, and the ladder's top bounds the worst
case for a slow reader.

### D5 — `crypto_version` stays 2; the KDF profile is orthogonal metadata

`crypto_version` selects the v2 key hierarchy and envelope scheme (`crypto.ts:14`). Argon2id
changes only how the root is produced; the HKDF labels, the wrapping scheme, the verifier
label and the recovery envelope are unchanged. Bumping `crypto_version` would ripple into
`recovery_rewrap`'s v2 gate (`recovery.rs:835-847`), the package's `cryptoVersion`, session
state and every `crypto_version` reader for no benefit. Explicitly rejected.

### D6 — At rest: one canonical JSON column `vault.kdf`, in the initial migration

`vault.kdf TEXT NOT NULL` holds the canonical serialization
(`{"algorithm":"argon2id","memory_kib":65536,"time_cost":3,"parallelism":1}`). The server
parses it into a typed value on every read and re-serializes on every write, so the stored
form cannot drift. The `iterations` column is **removed from the initial migration**
(`m20260901_000001_vault_centric_init.rs:17`), not carried and dropped later: there is no
population to backfill and no reason to keep two representations of one fact.

*Rejected:* a new migration that adds `kdf` and backfills `iterations` (dead code for a
population that does not exist). *Rejected:* keeping `iterations` as "the Argon2 time cost"
(misleading name, and a second meaning for an existing column). *Rejected:* four typed
columns (workable, but four columns that only ever move together, with no query use).

### D7 — One atomic rotation endpoint, replacing `/vault/password`

`POST /api/vault/credential` (session-required) is the only write that changes a password
credential. It takes the current verifier as a reauthentication proof, the observed
`credential_version` for CAS, and the complete new credential (salt, descriptor, verifier,
envelope). It never touches `vault`, `vaultiv`, `version`, `recovery_*` or `lock_epoch`.

`/vault/password` is deleted, not fixed: it has no client, and leaving a route that can
rewrite salt/verifier without an envelope is a permanent footgun. Password *change* (new
password, old-password reauth UI) becomes a future caller of the same endpoint — the
primitive is identical; only the UI and the "derive from the new password" step differ.

### D8 — No downgrades, ever, on any write

The server computes a rank from the descriptor (1–3, the ladder index) and rejects
`rank(new) < rank(stored)` with `400 KDF_DOWNGRADE` on both `/vault/credential` and
`/recovery/rewrap`. Rank is a policy order over the published ladder, not a measured
equivalence between parameter sets; the floor is the OWASP minimum, so any rung is an
acceptable destination above it. The client picks `max(calibratedTarget, storedProfile)` so a
recovery on a slow device reuses the vault's existing rung instead of failing or downgrading.
A malicious server cannot force a weaker profile silently: the client validates the served
descriptor against its own ladder before deriving, and a swapped profile simply fails the
verifier/envelope check (a DoS, not a compromise).

### D9 — Auto-upgrade after a password unlock, plus an explicit Settings action

The moment a password is typed is the only moment a rewrap is possible. So:

- **After a successful password unlock** (web login, re-auth, or session-unlock): if
  `storedRank < calibratedRank`, run the rotation once, in the background, after the vault is
  already open. A failure is a toast, never a failed unlock.
- **Settings → Security → "Vault protection"**: shows the current profile and an "Upgrade"
  action for users who only ever use the device key. This is the only path for them.
- **Never on device unlock**: there is no password in hand; there is nothing to derive.

The alternative — a blocking migration inside the unlock path — was rejected: it doubles the
user-visible KDF latency at the worst moment and turns a network failure into a failed
unlock.

### D10 — Package format 3 only, no reader adapter

The server is the only package producer. `cryptoParameters` becomes `{ salt, kdf }` and
`PACKAGE_FORMAT_VERSION` becomes 3 in lockstep (`apps/server/src/cloud/package.rs:32`,
`apps/client/src/lib/crypto/vault.ts:19`). The client reader accepts exactly 3 and rejects
anything else with "this backup was made by an unsupported version"; there is no v2 adapter
and no `iterations` fallback. A v2 package fails loudly rather than misparsing — which is the
correct outcome, since none exist in the wild.

### D11 — The client refuses to allocate what it did not ask for

A descriptor served by the server is validated against the local ladder **before** any
allocation. A `memory_kib` larger than the ladder's top (or an unknown algorithm) yields
`UNKNOWN_KDF_PROFILE` with "this vault needs a newer version of Voult" (the server's own
equivalent is `400 KDF_UNKNOWN`), never a 2 GiB allocation. The server's allowlist is the
second line of defence, not the first.

### D12 — PBKDF2 is deleted, not retained behind a flag

`ITERATIONS`, `PBKDF2_ITERATIONS`, the PBKDF2 branch of `deriveRootKey`, and every
`derivePasswordWrappingKey`/`createAuthKey` signature that takes an iteration count
disappear. Keeping a dead derivation path "just in case" is exactly the compatibility baggage
AGENTS.md rules out, and it would be the one code path nobody exercises. If a future profile
is ever retired, that is a separate decision with its own data-loss analysis; the ladder is
append-only so it should not happen.

---

## 4. Concrete shapes

### 4.1 Shared core — new `packages/vault-core/src/kdf.ts`

`kdf.ts` imports nothing from `crypto.ts`: once `crypto.ts` delegates root derivation to it, the
reverse import would be a cycle. It owns the descriptor, the ladder, the root derivation and
calibration.

```ts
export type KdfParams = {
  algorithm: "argon2id";
  /** KiB. Exactly a ladder rung; never free-form. */
  memory_kib: number;
  /** Argon2 passes. */
  time_cost: number;
  /** Always 1. Rejected otherwise. */
  parallelism: number;
};

export const KDF_LADDER_VERSION = 1;
export const KDF_LADDER: readonly KdfParams[];            // [19 MiB/t2, 32 MiB/t3, 64 MiB/t3]
export const KDF_FLOOR: KdfParams;                        // KDF_LADDER[0]

export function isKnownKdf(k: KdfParams): boolean;        // exact ladder match
export function kdfRank(k: KdfParams): number;            // ladder index + 1
export function describeKdf(k: KdfParams): string;        // UI/log label, non-secret

/** Root = Argon2id, 32 bytes. Throws on an unknown descriptor. */
export async function derivePasswordRoot(
  password: string,
  saltB64: string,
  kdf: KdfParams,
): Promise<Uint8Array>;

/** Runs each rung once on random input; highest under budget, never below the floor. */
export async function calibrateKdf(options?: {
  budgetMs?: number;
  now?: () => number;
}): Promise<{ kdf: KdfParams; measuredMs: number }>;
```

`derivePasswordRoot` stays `async` even though noble's call is synchronous, so a later move
into a Worker does not change a single call site.

`crypto.ts` keeps the HKDF labels, `hkdfExpand`, the verifier and the composite entry point:

```ts
/** One root derivation, two HKDF expands, one verifier. The only password entry point. */
export async function derivePasswordKeys(
  password: string,
  saltB64: string,
  kdf: KdfParams,
): Promise<{ authKey: CryptoKey; wrappingKey: CryptoKey; vaultVerifier: string }>;
```

`derivePasswordWrappingKey` and `createAuthKey` are removed rather than kept as a second way
in: the unlock and login paths need both keys, and with Argon2 calling them separately would
mean two ~590 ms derivations (the extension already does exactly that at `vault.ts:513-516`,
as does the web composite at `flows.ts:36-37`). Callers that genuinely need only one key (the
package reader at `import.ts:126`, the verifier at `:154`) call `derivePasswordKeys` and
discard the other — still one derivation. The two client-side copies of the composite helper
(`apps/client/src/lib/auth/flows.ts:35-40`, `apps/client/src/lib/auth/utils.ts:53-56`) are
deleted in favour of the shared one. One derivation per unlock becomes the rule.

### 4.2 Wire — `GET /api/get_crypto_params`

```json
{
  "salt": "16-byte base64",
  "kdf": { "algorithm": "argon2id", "memory_kib": 65536, "time_cost": 3, "parallelism": 1 },
  "recovery_salt": "16-byte base64 or null",
  "has_recovery": true
}
```

`iterations` is removed. `credential_version` is deliberately **not** added here: the upgrade
path runs after a session exists, so it reads the counter from `/auth` / `get_vault` instead
of widening the unauthenticated surface. The existing pre-auth existence oracle
(`get_crypto_params.rs:76-78`, roadmap P1) is unchanged in kind.

`/auth`, `/get_vault` add `kdf` (replacing `iterations`) and `credential_version` (post-auth
only). `/update_vault` echoes `kdf` instead of `iterations`. `register` and `/vaults` accept
`kdf` instead of `iterations` and reject `crypto_version != 2`
(`UNSUPPORTED_CRYPTO_VERSION`), removing the `unwrap_or(1)` path at `register.rs:125`.

### 4.3 Wire — `POST /api/vault/credential`

```json
{
  "current_vault_verifier": "base64 32B",
  "credential_version": 0,
  "new_salt": "base64 16B",
  "new_kdf": { "algorithm": "argon2id", "memory_kib": 65536, "time_cost": 3, "parallelism": 1 },
  "new_vault_verifier": "base64 32B",
  "new_vault_key_wrap": "base64 48B",
  "new_vault_key_wrap_iv": "base64 12B"
}
```

Success `200`:

```json
{ "vault_id": "…", "credential_version": 1, "kdf": { … }, "lock_epoch": 0 }
```

Errors (all before any DB write unless stated):

| Status | Code | When |
|---|---|---|
| 401 | `SESSION_REQUIRED` | no session |
| 401 | `AUTH_FAILED` | `current_vault_verifier` does not match the stored value (constant-time compare) |
| 400 | `INVALID_INPUT` | missing/blank fields, bad base64 lengths, `credential_version < 0` |
| 400 | `KDF_UNKNOWN` | descriptor is not an allowlisted rung |
| 400 | `KDF_DOWNGRADE` | `rank(new) < rank(stored)` |
| 409 | `CREDENTIAL_STALE` | CAS lost (`rows_affected == 0`) |
| 500 | `DATA_INTEGRITY_ERROR` | stored `kdf` column does not parse |

Implementation shape (Rust): fetch by `session_vault_id`, compare verifiers with a
constant-time compare (XOR-accumulate over the fixed 32-byte values, the same pattern the
client uses at `recover.ts:275-280`; no early exit, no `==`), then

```rust
Vaults::update_many()
    .col_expr(Salt, Expr::value(new_salt))
    .col_expr(Kdf, Expr::value(new_kdf_canonical_json))
    .col_expr(VaultVerifier, Expr::value(new_verifier))
    .col_expr(VaultKeyWrap, Expr::value(new_wrap))
    .col_expr(VaultKeyWrapIv, Expr::value(new_wrap_iv))
    .col_expr(CredentialVersion, Expr::col(CredentialVersion).add(1))
    .filter(Id.eq(vault_id))
    .filter(CredentialVersion.eq(body.credential_version))
```

No session renewal, no `lock_epoch` change, no `version` change.

### 4.4 Recovery rewrap

`RewrapRequest` (`recovery.rs:720-733`) changes `new_iterations: i32` → `new_kdf: KdfParams`
and validates it through the same `kdf::validate_for_write` + no-downgrade rule. Everything
else about the flow is unchanged: the same challenge/proof, the same CAS on
`credential_version`, the same column discipline (`recovery.rs:736-745`). A recovery is
therefore also a profile upgrade when the recovering device calibrates higher than the vault's
current rung.

### 4.5 Package 3

```json
{
  "packageFormatVersion": 3,
  "cryptoParameters": {
    "salt": "…",
    "kdf": { "algorithm": "argon2id", "memory_kib": 65536, "time_cost": 3, "parallelism": 1 }
  }
}
```

Server `package.rs` emits 3 and `parse_header` accepts exactly 3. Client `import.ts` requires
`pkg.packageFormatVersion === 3` and `cryptoParameters.kdf`; a package missing either is
rejected with an explicit unsupported-format error. No `iterations` branch exists.

### 4.6 Database

Edit the existing initial migration (`apps/server/migration/src/m20260901_000001_vault_centric_init.rs`):

- replace `.col(integer(Vault::Iterations).not_null())` at `:17` with
  `.col(string(Vault::Kdf).not_null())`;
- rename the `Iterations` iden enum entry to `Kdf`;
- update `apps/server/src/entity/vault.rs:12` to `pub kdf: String`.

No new migration and no backfill. SeaORM will not re-run an edited migration, so an existing
database keeps the old shape and every vault read fails loudly with
`no such column: vault.kdf`. Delete the development databases before running:

```sh
rm -f "$HOME/Library/Application Support/Voult/voult.db" apps/server/voult.db
```

and clear the browser's site data (or create a vault with a fresh id) so the client does not
try to restore a selection that no longer exists. This is the same clean-start instruction the
migration crate already carries (`apps/server/migration/src/lib.rs:4-7`). Every test fixture
that builds a `vault::Model` or posts a registration body must set `kdf` instead of
`iterations` (`cloud/package.rs:194-215`, `recovery.rs:1231`, `cloud/mirror.rs:1105`,
`cloud_endpoints.rs:1662`, `register.rs:312-328`).

---

## 5. Migration paths, case by case

### 5.1 New vault

`prepareSignupFlow` (`signup.ts:39-107`) calls `calibrateKdf()` (cached), derives with the
chosen rung, and puts the same descriptor in `POST /register`. Nothing else about creation
changes; the recovery-file-before-registration invariant (`registration.ts:8-35`) is
untouched.

### 5.2 Rung upgrade, password typed

There is no legacy population, but the same path is what moves a vault from a lower rung to a
higher one when the user unlocks on a faster device — and it is the mechanism every future KDF
change will use.

1. `get_crypto_params` → stored `kdf` + salt.
2. `derivePasswordKeys(password, salt, storedKdf)` → verifier + wrap key (one KDF run).
3. `/auth`, unwrap, open. The vault is usable at this point.
4. If `kdfRank(stored) < kdfRank(calibratedTarget)`: derive the new credential with a fresh
   salt and the target, wrap the same `vaultKeyRaw`, **unwrap it again and compare bytes**
   (the `completeRecovery` pattern, `recover.ts:210-219`), then `POST /vault/credential`
   with the verifier from step 2. The upgrade receives its **own copy** of `vaultKeyRaw`
   (the unlock path zeroes its copy at `flows.ts:256`) and zeroes it in a `finally`, as
   `abandonPendingRecovery` does at `recover.ts:103-110`. `credential_version` is read fresh
   from `get_vault` for this call, never from `LockMetadata`: the metadata may be stale after
   another device's rotation, and the CAS — not the cache — is what makes the write safe.
5. On success: update any in-memory `LockMetadata` and invalidate `["cryptoParams", vaultId]`
   and `["vault"]` so no tab reuses stale parameters.
6. On failure: leave everything as it was; the credential on the server is still the old one.
   Show "Protection upgrade didn't finish; it will retry next time you unlock."

### 5.3 Device-key-only user

Nothing happens until they use **Settings → Security → Vault protection → Upgrade**. That
action prompts for the master password, derives the current verifier (needed for the reauth
proof), then runs 5.2 steps 4–6. A user who only ever device-unlocks stays on their current
rung — still at or above the floor — until they choose to upgrade.

### 5.4 Restore from a backup, and recovery

`importVaultFromCloud` (`import.ts:39-208`) already holds the password and derives the
credential. It requires package format 3, derives with the package's `kdf`, and after
`submitRegistration` runs the same rung upgrade if the local device calibrates higher. If the
upgrade fails, the vault is restored at its package rung and the next password unlock retries.

Recovery (`apps/client/src/lib/auth/flows/recover.ts`) ends in `completeRecovery`, which
already derives a new password credential and calls `/recovery/rewrap` with a local
unwrap-and-compare (`:205-240`). It sends `new_kdf = max(calibratedTarget, storedKdf)` instead
of the constant. `verifyRecoveryKey` already fetches `params.kdf`; `PendingRecovery` must carry
it across the screen boundary alongside `credentialVersion`, for the same reason that field is
carried (`recover.ts:71-85`). A vault recovered on a slower device therefore keeps its existing
rung instead of attempting a downgrade, which the server would reject anyway.

### 5.5 A vault that is never unlocked again

It stays on the rung it was created with, which is at or above the OWASP floor — there is no
weaker legacy credential anywhere, because every vault is born on Argon2id. Nothing needs
migrating, and nothing is exposed by the user's absence. If a newer device would calibrate
higher, the vault upgrades the next time the password is typed (auto-upgrade) or when the user
runs the Settings action. The server cannot rewrap on its own — it has no key and no password —
and it never needs to.

This is the entire answer to "what happens to a vault whose user never logs in again":
nothing bad, unlike a deployment that had already shipped 60k PBKDF2 vaults.

### 5.6 Extension

The extension derives with the profile returned by `get_crypto_params` and nothing else
(`apps/extension/src/lib/api.ts:37-42`, `background/vault.ts:513-516`). It does not
calibrate, does not rotate, and has no UI for either. After the web app upgrades a vault, the
extension's next unlock simply derives with the new profile. A vault opened only in the
extension stays on its rung — a deliberate scope boundary, because the extension has no place
to explain a credential write or its failure.

### 5.7 Races, stale caches, lost responses

Rotations still exist (rung upgrades, recovery rewrap), so the race handling stays:

- **Two devices rotate at once:** the CAS lets one win; the loser gets `409
  CREDENTIAL_STALE`, re-fetches, sees the stored descriptor already equals its target, and
  treats it as success.
- **Lost response after commit:** the retry can arrive with the *old* verifier, because the
  stored one changed with the commit. The endpoint checks the reauth proof before the CAS, so
  this surfaces as `401 AUTH_FAILED`, not `409`. The client therefore treats `401` and `409`
  identically for convergence: refetch the vault's credential metadata, and if the stored
  descriptor already equals the intended target, success; only otherwise is it a real error.
  The vault is open throughout and the ciphertext never moved.
- **Stale params or envelope after another device's rotation:** today this surfaces as a false
  "Incorrect password" (cached salt + envelope, new server-side credential). Every password
  unlock path (`unlockWithPassword`, `reauthenticateAndUnlock`, `passwordLoginFlow`) gains one
  retry: on unwrap failure or a `401` from `/auth`, refetch `get_crypto_params` + `get_vault`,
  and if the salt or descriptor actually changed, re-derive and retry once; only then report a
  wrong password. To make that possible without two parameter paths, `passwordLoginFlow` takes
  `(vaultId, password)` and fetches params itself — all three callers already fetch them
  immediately before (`open.ts:17`, `import.ts:51-57`, `:206-207`).
- **App closed mid-rotation:** the server write is a single UPDATE inside one statement; the
  row is either old or new. Both open. No repair step.
- **Recovery racing a rotation:** `completeRecovery`'s CAS can now lose to an ordinary rung
  upgrade, not only to another recovery. The `CREDENTIAL_STALE` copy (`recover.ts:314-316`) is
  reworded to say the vault's credential changed and the recovery file must be reopened; the
  flow itself already recovers correctly by restarting at step 1.

---

## 6. Trust boundary — what this must not break

| Invariant | How it is preserved |
|---|---|
| **Zero knowledge** | The server still never receives the password, the vault key, or plaintext. The new fields are a public algorithm descriptor, a salt, a derived verifier and ciphertext. No KDF ever runs server-side. |
| **No new secret in logs** | Log `vault_id`, `describeKdf(...)` and `credential_version`. Never the verifier, envelope, salt bytes or password. The rotation handler logs only outcome + ids, at `info` on success and `warn` on stale/refused. |
| **Session semantics** | The vault id comes from `session_vault_id` (`session_auth.rs:6-15`), never the body. The endpoint does not renew, purge or re-scope the session; the cookie already names the vault. `current_vault_verifier` is a reauth proof, not an identity. |
| **Per-vault namespacing** | Unchanged: OPFS `file:voult-<id>.db`, IndexedDB `vault:<id>`, `lock_epoch`, selection epoch. The profile is per-vault metadata; calibration is device-global and only affects credentials this device creates or upgrades. |
| **Rule R1 (recovery)** | The recovery envelope wraps `vaultKeyRaw` directly (`crypto.ts:536`; `entity/vault.rs:43-49`). Rotation must leave `recovery_verifier`, `recovery_salt`, `recovery_wrap`, `recovery_wrap_iv`, `recovery_created_at` byte-identical — asserted in tests. A second recovery with the same file must still work after a KDF rotation. |
| **Recovery proof protocol** | The HMAC labels (`recovery-verify-v1`, `recovery-proof-v1`) and the challenge/CAS flow are untouched. Only the KDF field inside `RewrapRequest` changes. |
| **Document CAS** | `version` is not touched by rotation. Bumping it would invalidate every pending sync intent's `base_version` (`architecture.md`, `conflict-resolution.md`). |
| **COOP/COEP** | Unchanged (`main.rs:304-305`, `public/_headers`). No WASM is added, so there is no new `SharedArrayBuffer`, asset or header requirement. |
| **MV3 CSP** | Unchanged (`manifest.json:34-35`). This is the reason WASM Argon2 was rejected (D1). |
| **No new network surface** | One authenticated route replaces one authenticated route. No new unauthenticated endpoint; `get_crypto_params` is not widened. |
| **DoS resistance** | The client validates the served descriptor against its ladder before allocating (D11). The server exact-matches the allowlist, so no vault can be stored at `memory_kib = 2^31`. A malicious server can still refuse to serve params — availability, not confidentiality. |
| **Verifier replay (separate P0)** | Not fixed and not worsened: the rotation endpoint re-sends the verifier, which the client already sends to `/auth`. A stolen verifier stops working after rotation only incidentally; the real fix is the separate item. |
| **Server rollback (separate P1)** | A malicious or compromised server can replay a pre-upgrade row (old salt, old descriptor, old verifier, old envelope) and the client will unlock under the old profile. No client-side signal distinguishes it from the truth. This is the existing rollback limitation (`ROADMAP:75`), not a new one, and the KDF work neither fixes nor worsens it. What the KDF does fix is offline guessing after a copy of the row leaks. |

New attack surface introduced: a session holder who also knows the current verifier can
replace the credential. That requires strictly more than today's `/vault/password`, which
requires only the session. The worst a cookie-only attacker can do is fail the verifier
check; the worst a verifier-holding attacker can do is deny password unlock, while recovery
and the device envelope remain (R1). That is the same authority the verifier already confers
on `/auth`, so it is not a new privilege class. The verifier proof also makes the route
useless to a blind CSRF attacker, who cannot produce it — a property `/vault/password` lacks.

---

## 7. Files to touch

### New

| Path | Purpose |
|---|---|
| `packages/vault-core/src/kdf.ts` | Descriptor type, ladder, root derivation, calibration, rank. |
| `packages/vault-core/test/kdf.test.ts` | KATs, ladder validation, calibration boundaries, downgrade rank. |
| `packages/vault-core/scripts/kdf-bench.mjs` | Reproducible per-rung timing report (dev tool, not shipped). |
| `apps/server/src/kdf.rs` | Rust mirror: `KdfParams`, canonical storage form, allowlist validation, rank. |
| `apps/server/src/endpoints/vault_credential.rs` | The rotation endpoint + handler tests. |
| `apps/client/src/lib/auth/kdf-upgrade.ts` | Detect, derive, verify round-trip, rotate, retry/converge, cache invalidation. |
| `apps/client/src/lib/queries/vaultCredential/{api.schema.ts,query.ts}` | Typed client for the new endpoint. |
| `apps/client/src/lib/settings/kdf-section.tsx` | Settings → Security "Vault protection" card + password prompt. |

### Edit

**Shared core**
- `packages/vault-core/src/crypto.ts` — delete `ITERATIONS`/`PBKDF2_ITERATIONS` and the
  PBKDF2 branch of `deriveRootKey`; delegate to `kdf.ts`; remove
  `derivePasswordWrappingKey`/`createAuthKey` in favour of `derivePasswordKeys`. HKDF labels
  and recovery primitives unchanged.
- `packages/vault-core/src/index.ts` — export the KDF surface; drop the removed helpers.
- `packages/vault-core/src/schema.ts:435-440` — `LockMetadata.kdf` instead of `iterations`;
  `:562`, `:582` — `VaultResponse` / `UpdateVaultResponse`.
- `packages/vault-core/package.json` — add `"@noble/hashes": "2.4.0"` (exact).

**Server**
- `apps/server/migration/src/m20260901_000001_vault_centric_init.rs:17` — `Kdf` string column
  replaces `Iterations`; rename the iden entry. No new migration, no `migration/src/lib.rs`
  change.
- `apps/server/src/entity/vault.rs:12` — `kdf: String`; `:44` — the Rule R1 comment says
  "never HKDF(PBKDF2(password))", reword to the password-derived wrapping key.
- `apps/server/migration/src/m20261013_000006_vault_recovery.rs:7` — same comment wording
  (no schema change).
- `apps/server/src/endpoints/get_crypto_params.rs:16-37`, `:92-100`.
- `apps/server/src/endpoints/auth.rs:27`, `:121-141` (+ `credential_version`).
- `apps/server/src/endpoints/register.rs:22`, `:125`, `:142-163`, test body `:312-328` — accept
  `kdf`, require `crypto_version == 2`.
- `apps/server/src/endpoints/vaults.rs:19`, `:127-145`.
- `apps/server/src/endpoints/get_vault.rs:22`, `:82-92` (+ `credential_version`).
- `apps/server/src/endpoints/update_vault.rs:31`, `:165-173`.
- `apps/server/src/endpoints/recovery.rs:68-73`, `:720-733`, `:786-791`, `:850-887` — remove
  the iteration constants; validate `new_kdf` through `kdf.rs`.
- `apps/server/src/endpoints/mod.rs` + `main.rs:340` — drop `update_vault_password`, wire
  `vault_credential`; add `mod kdf;` to `main.rs`.
- `apps/server/src/endpoints/update_vault_password.rs` — **deleted**.
- `apps/server/src/cloud/package.rs:32`, `:44-48`, `:167-170`, `:194-215` and its tests.
- `apps/server/src/cloud/mirror.rs:1105`, `:1366`; `endpoints/cloud_endpoints.rs:1662`,
  `:1703` — fixtures.

**Web client**
- `apps/client/src/lib/crypto/index.web.ts` — re-export the KDF surface; drop the
  `derivePasswordWrappingKey`/`createAuthKey` re-exports in favour of `derivePasswordKeys`.
- `apps/client/src/lib/auth/utils.ts:53-56` — delete the duplicate; use shared
  `derivePasswordKeys`.
- `apps/client/src/lib/auth/flows.ts:35-40`, `:103-124`, `:183`, `:224-260` — stored profile,
  single derivation, stale-metadata retry, post-unlock upgrade hook.
- `apps/client/src/lib/auth/flows/signup.ts:2`, `:63`, `:89` — calibrated profile.
- `apps/client/src/lib/auth/flows/login.ts:22-30` — fetch params itself; derive with the
  returned descriptor; one retry on stale params.
- `apps/client/src/lib/auth/flows/recover.ts:3`, `:71-85`, `:205-240`, `:314-316` — `new_kdf`,
  stored descriptor across the screen boundary, target selection, stale copy.
- `apps/client/src/lib/auth/lock.ts:107` — lock metadata carries `kdf`.
- `apps/client/src/lib/vault/open.ts:17-18` — `passwordLoginFlow(vaultId, password)`; params
  are fetched inside the flow now.
- `apps/client/src/lib/vault/import.ts:49-57`, `:87-120`, `:126`, `:154`, `:164-178`,
  `:206-207` — package format 3 only, derive with `kdf`, post-restore upgrade.
- `apps/client/src/lib/crypto/vault.ts:19`, `:130-186` — `CryptoParameters.kdf`, format 3.
- `apps/client/src/lib/state/type.ts:46-60` — `VoultPackage.cryptoParameters`.
- `apps/client/src/lib/queries/{cryptoParams,logIn,SignUp,vaults,recovery}/api.schema.ts` —
  `kdf` / `credential_version`.
- `apps/client/src/app/settings/index.tsx` + `lib/settings/device-unlock-section.tsx`
  neighbourhood — mount the "Vault protection" section.

**Extension**
- `apps/extension/src/lib/api.ts:37-42` — params type carries `kdf`.
- `apps/extension/src/background/vault.ts:513-516` — derive with `params.kdf`.
- `apps/extension/src/lib/api.ts` `fetchVault`/`postUpdateVault` types come from vault-core
  and update automatically.

**Docs**
- `AGENTS.md` — the crypto bullet and the recovery/Rule R1 paragraph.
- `SECURITY_AND_FEATURE_ROADMAP.md:56` — mark the item and add a changelog line; update the
  "Client-side v2 encryption" bullet at `:15`; note the rotation primitive under the P1
  password-change item at `:71`.
- `apps/client/architecture.md` — KDF profile section.
- `docs/Vault-recovery-flow.md` — one line: rewrap installs the current profile; R1 unchanged.

### Do not touch

- `packages/vault-core/src/recovery-pdf.ts`, `recoveryAad`, `RECOVERY_*` labels, and the
  challenge/proof verification in `recovery.rs`.
- `apps/server/src/session_auth.rs`, the cookie middleware, `lock.rs`.
- `apps/server/src/main.rs:304-305` COOP/COEP and `public/_headers`.
- `packages/vault-core/src/merge.ts`, `apps/client/src/lib/sync/**`, the intent schema.
- `apps/client/src/lib/crypto/device-key.ts` — the device envelope is independent of the
  password KDF.
- `apps/client/src/lib/sqlite/**`.
- `/auth`'s verifier comparison (separate P0), `/update_vault` bounds (separate P0).
- The password/device envelope AAD gap (P2).

---

## 8. Phases

Each phase leaves the tree building, typechecking and usable.

### M0 — Shared KDF core, vectors, calibration (no wire change)

Scope: add `kdf.ts`, the pinned dependency, tests and the bench script. `crypto.ts` and every
call site stay as they are; no app code imports the new module yet, so shipped bundles do not
change.

Acceptance:
- `cd packages/vault-core && npm install && npm test` — new KDF suite passes alongside the
  existing suite.
- Known-answer tests: `argon2id` at all three ladder rungs match `node:crypto.argon2` on Node
  24+ (experimental; present here: v24.19.0); the cross-check **skips** when unavailable,
  exactly like the poppler/Ghostscript checks in `recovery-pdf`. Pinned vectors are committed
  as constants so CI does not depend on the Node version.
- Adversarial cases: unknown algorithm, `parallelism: 4`, `memory_kib: 2^31`, a 15/17-byte
  salt, a non-canonical descriptor, and an off-ladder tuple — all rejected before derivation.
- `calibrateKdf({ budgetMs: 1 })` returns the floor; `{ budgetMs: 60_000 }` returns the top;
  the result is always a ladder member.
- `cd packages/vault-core && npm run build && node scripts/kdf-bench.mjs` reproduces the
  §2.3 table on the host.
- `cd apps/client && npx tsc --noEmit` and `cd apps/extension && npx tsc --noEmit` still pass.

### M1 — Schema, wire contract, packages, all derive sites

Scope: edit the initial migration and entity, every endpoint shape, package 3, web and
extension deriving from the stored descriptor, new vaults created on the calibrated rung.
This is one atomic commit because the column and every reader must move together. PBKDF2 is
deleted here.

Acceptance:
- `cd apps/server && cargo test` — full suite, including new cases: registration without `kdf`
  (or with an unknown descriptor) is rejected; `crypto_version: 1` is rejected;
  `get_crypto_params` returns the stored descriptor; package 3 carries it; `parse_header`
  rejects version 2.
- `npx tsc --noEmit` in client and extension.
- Delete the dev databases, `cargo run`, create a vault:
  `sqlite3 "$HOME/Library/Application Support/Voult/voult.db" "select id, kdf from vault"` →
  the row carries the descriptor returned by `get_crypto_params`, and unlocking works on web
  and in the extension.
- A v2 package fixture (`packageFormatVersion: 2`, `iterations`) is rejected with the
  unsupported-format message. A version 3 package round-trips through the cloud endpoints.
- `curl` with a body containing `iterations` and no `kdf` → `400 INVALID_INPUT`, no row
  written.

### M2 — Rotation endpoint and client upgrade

Scope: delete `/vault/password`, add `POST /vault/credential`, `kdf-upgrade.ts`, the Settings
card, stale-metadata retry, auto-upgrade after password unlock.

Acceptance:
- `cargo test` — rotation cases: happy path; wrong `current_vault_verifier` → 401 and **no**
  write; CAS loss → 409; downgrade → 400; `recovery_*`, `version` and the ciphertext unchanged
  after success; `credential_version` +1.
- Manual: create a vault on a device calibrated to the floor (throttle the CPU, or force the
  floor via a test hook), then unlock on a fast device — the row moves to a higher rung,
  `credential_version` +1, `version` and the `vault` ciphertext unchanged.
- Manual: wrong password at the lock screen → no `credential_version` change.
- Manual: two tabs upgrade the same vault simultaneously → one rotates, the other converges
  to success or a benign "already upgraded" toast; neither leaves a false "Incorrect
  password".
- Manual: `kill -9` the server immediately after clicking Upgrade (or use a proxy that drops
  the response), restart, unlock — opens normally, row is at exactly one of the two profiles.
- Manual: Settings → Security shows the current rung and an Upgrade action; the action
  requires the password.
- Manual: lock a tab, upgrade the same vault in another tab, then unlock the first — it opens
  via the retry path instead of reporting a wrong password.

### M3 — Hardening, docs, cleanup

Scope: downgrade/unknown-profile handling end to end, recovery on a fresh vault, package
format tests, docs, roadmap, removal of dead code (`createVoultPackage` if still unused),
final sweep for stray `iterations`.

Acceptance:
- `cargo test`; `npm --prefix packages/vault-core test`; both typechecks; `npm run build:web`;
  `cd apps/extension && npm run build`.
- Recovery of a fresh vault installs the recovering device's target rung; the same recovery
  file recovers the vault a second time afterwards (Rule R1 holds across a KDF rotation).
- A Drive backup of an Argon2id vault restores onto a clean database.
- `grep -rn iterations apps packages --include='*.ts' --include='*.rs' | grep -v node_modules`
  returns no field, parameter or wire uses (explanatory comments about the
  removed algorithm are fine); `grep -rn PBKDF2 apps packages` likewise finds
  only comments documenting its removal.
- `AGENTS.md`, the roadmap and `architecture.md` describe the implemented state; the roadmap
  item is marked done.

---

## 9. Overlaps with other roadmap items (not fixed here)

| Item | Seam |
|---|---|
| **P0 — request/protocol bounds** (`ROADMAP:61`) | This plan validates `kdf` on `/register`, `/vaults`, `/vault/credential`, `/recovery/rewrap` and requires `crypto_version == 2` on registration. `/auth`, `/update_vault`, ciphertext caps and cross-instance limits remain. |
| **P1 — atomic password change** (`ROADMAP:71`) | `/vault/credential` is the atomic rewrap primitive that item needs. This plan does **not** ship the old-password/new-password UI, so the item stays open. |
| **P1 — vault format/KDF migrations** (`ROADMAP:34`) | This is the KDF half: a versioned profile plus the rewrap mechanism future changes will use. No data migration ships because there are no released vaults; document-format migrations remain. |
| **P0 — reusable verifier** (`ROADMAP:57`) | Untouched. The new endpoint re-sends the verifier, which is the existing protocol. |
| **P1 — server rollback protection** (`ROADMAP:75`) | A server can replay a pre-upgrade credential; the client cannot detect it. Documented in §6, not fixed here. |
| **P2 — envelope AAD** (`ROADMAP` P2) | The newly wrapped password envelope is still AAD-less. Adding AAD later will require another rotation; the endpoint from this plan is the mechanism. |
| **P0 — security tests** (`ROADMAP:62`) | Adds KDF KATs, downgrade/CAS/lost-response tests, but does not close the broader client/server integration-test item. |

---

## 10. Verification detail

### 10.1 Manual database checks

```sh
DB="$HOME/Library/Application Support/Voult/voult.db"
sqlite3 "$DB" "select id, kdf, credential_version, version from vault"
# after an upgrade: kdf switched, credential_version +1, version unchanged
sqlite3 "$DB" "select recovery_verifier, recovery_wrap from vault where id='…'"
# before/after a rotation: byte-identical
```

### 10.2 KAT strategy

The pinned vectors are generated once from `node:crypto.argon2` (an implementation
independent of `@noble/hashes`) and committed as constants, so CI does not depend on the Node
version. Where `crypto.argon2` exists, the suite additionally asserts noble == node for every
ladder rung on random inputs; where it does not, that test skips with a printed reason. This
mirrors the recovery-PDF approach (poppler/Ghostscript skipped, not failed, when absent) and
avoids a test that silently asserts the library against itself.

### 10.3 Assumption + fallback

Real-device performance is not knowable from this machine. The calibration budget (700 ms)
and the floor are the guard: if a device cannot meet the budget even at 19 MiB/t=2, the floor
is used anyway (security over latency) and the UI shows a longer "Unlocking…" state. If field
measurements show the floor exceeding ~2.5 s on target hardware, the fallback is to move the
derivation into a Web Worker — not to lower the floor and not to add WASM, both of which were
rejected above.

---

## 11. Implementation log (2026-10-28)

Shipped as planned, with these concrete choices made while implementing:

- `packages/vault-core/src/kdf.ts` is the single registry. `KdfParams` is one
  object type (only Argon2id exists); `kdfEquals` was added for stale-metadata
  comparisons.
- `bytes.ts` was extracted so `kdf.ts` can decode salts without importing
  `crypto.ts` (which imports `kdf.ts`).
- The initial migration was edited in place (no `000008`). `vault.kdf` holds
  canonical JSON. `KdfParams::parse_stored` treats an off-ladder stored value as
  `DATA_INTEGRITY_ERROR`, not as a descriptor to interpret.
- `POST /vault/credential` returns `lock_epoch` for parity with recovery rewrap,
  and rejects non-v2 rows.
- The auto-upgrade is deferred to an idle slot (`requestIdleCallback`, 250 ms
  fallback) because the second Argon2 run is on the main thread. The Settings
  action is awaited.
- The recovery client carries `storedKdf` across the two screens and selects
  `max(calibrated, stored)`.
- The web export and the extension build succeed with `@noble/hashes` bundled;
  no WASM asset and no CSP change.

Verification performed:

- `cargo test`: **114 passed**.
- `packages/vault-core`: **125 passed, 5 skipped** (poppler/Ghostscript absent).
- `npx tsc --noEmit`: client and extension pass.
- `npm run build:web` and extension `npm run build` pass.
- Live-server end-to-end with real client crypto: register → rotate → auth →
  unwrap → decrypt; downgrade and wrong-verifier rejection; recovery rewrap →
  auth; a second recovery unlock with the same file (Rule R1). The throwaway
  scripts lived in the temp directory, not the repo.
- `sqlite3` confirmed canonical `kdf` JSON and `credential_version` 0→1 with
  `version` unchanged.

Not exercised: the Settings upgrade card and the signup/unlock UI in a real
browser (no desktop browser was attached to the session). Those paths are
typechecked and built but have not been clicked through.
