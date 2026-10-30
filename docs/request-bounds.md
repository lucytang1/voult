# Request bounds — the write-boundary contract

Every write endpoint validates the exact shape below **before any database
work**. A shape failure returns `400` with
`{"error_msg": "<field> must be <expected>", "code": "INVALID_INPUT"}`. The
transport body cap returns `413 {"code": "PAYLOAD_TOO_LARGE"}`.

Two implementations, one contract:

- Server (authoritative): `apps/server/src/endpoints/validate.rs`
- Client mirror: `packages/vault-core/src/bounds.ts`

Do not add a length, an iteration bound, or a supported version anywhere else.
When the KDF-profile work changes the numbers, it changes them in those two
files (and `PBKDF2_ITERATIONS`) only.

## Constants

| Constant (server / client) | Value | Why |
|---|---|---|
| `SALT_LEN` / `SALT_BYTES` | 16 B | `generateSalt()` in `vault-core/src/crypto.ts`; PBKDF2 salt and recovery HKDF salt. |
| `IV_LEN` / `IV_BYTES` | 12 B | 96-bit AES-GCM nonce used by `encrypt` and `wrapKeyBytes`. |
| `VERIFIER_LEN` / `VERIFIER_BYTES` | 32 B | HMAC-SHA256 output (`vault_verifier`, `recovery_verifier`). |
| `KEY_WRAP_LEN` / `KEY_WRAP_BYTES` | 48 B | 32-byte wrapped key + 16-byte GCM tag (both envelopes). |
| `PROOF_LEN` / `PROOF_BYTES` | 32 B | Recovery proof HMAC. |
| `CHALLENGE_LEN` | 32 B | Server-minted recovery challenge. |
| `MIN_CIPHERTEXT_LEN` / `MIN_VAULT_CIPHERTEXT_BYTES` | 17 B | GCM tag + at least one payload byte. |
| `MAX_CIPHERTEXT_LEN` / `MAX_VAULT_CIPHERTEXT_BYTES` | 4 MiB | Chosen blob ceiling (≈6,000 average items). |
| `MAX_PACKAGE_LEN` / `MAX_PACKAGE_BYTES` | 6 MiB | Ciphertext as base64 + envelopes. |
| `MAX_REMOTE_ID_LEN` / `MAX_REMOTE_ID_LENGTH` | 512 chars | Provider file ids / revisions. |
| `KDF_ITERATIONS_MIN` / `KDF_ITERATIONS_WRITE_FLOOR` | 60,000 | Write-time floor; the value every current client writes. |
| `KDF_ITERATIONS_MAX` / `KDF_ITERATIONS_CEILING` | 2,000,000 | Bounds unlock cost on the client. |
| — / `KDF_READ_FLOOR` | 60,000 | Absolute floor for deriving from an existing row; may lag the write floor. |
| `SUPPORTED_CRYPTO_VERSION` | 2 | Only version any producer emits. |
| `MAX_JSON_BODY_BYTES` | 12 MiB | `base64(6 MiB)` = 8,388,608 chars + framing. |

Derived invariants (compile-time on the server, unit-tested in both):
`base64(4 MiB) < 6 MiB < base64⁻¹(12 MiB)`.

## Shape rules

**UUID** — canonical lowercase hyphenated, version 4. Uppercase, braced,
unhyphenated, nil, and non-v4 forms are refused. Every producer is
`crypto.randomUUID()` or `uuidv4()`.

**Base64** — standard alphabet `A–Z a–z 0–9 + /`, length a multiple of 4,
padding only at the end, canonical trailing bits (zero). Outer whitespace is
trimmed; interior whitespace is refused. This matches `base64` 0.22's
`STANDARD` engine (`RequireCanonicalPadding`, `decode_allow_trailing_bits =
false`) and the client's `btoa` output. URL-safe (`-_`) and unpadded forms are
refused.

**KDF** — `KDF_ITERATIONS_MIN <= iterations <= KDF_ITERATIONS_MAX`. Checked on
writes only; reads keep honouring older profiles, and the client's
`deriveRootKey` enforces `KDF_READ_FLOOR`.

## Endpoints

### `POST /api/register` (unauthenticated)

| Field | Shape |
|---|---|
| `vault_id` | canonical UUID v4 |
| `vault_verifier` | base64, 32 B |
| `salt` | base64, 16 B |
| `iterations` | 60,000–2,000,000 |
| `vaultiv` | base64, 12 B |
| `vault` | base64, 17 B–4 MiB decoded |
| `crypto_version` | required, `2` |
| `vault_key_wrap` | base64, 48 B |
| `vault_key_wrap_iv` | base64, 12 B |
| `recovery_verifier` | base64, 32 B |
| `recovery_salt` | base64, 16 B |
| `recovery_wrap` | base64, 48 B |
| `recovery_wrap_iv` | base64, 12 B |

### `POST /api/vaults` (session)

Same rules for the twelve crypto fields. Additionally: `vault_verifier` is
required (never defaulted), `crypto_version` is required, and `vault_id` — when
present — must be canonical and equal the session vault, else `403
VAULT_MISMATCH`.

### `POST /api/auth` (unauthenticated)

| Field | Shape |
|---|---|
| `vault_id` | canonical UUID v4 |
| `vault_verifier` | base64, 32 B |

Unknown vault and wrong (well-formed) verifier both return the identical `401
AUTH_FAILED`. A malformed verifier is a `400`, which reveals nothing about the
row.

### `POST /api/update_vault` (session)

| Field | Shape |
|---|---|
| `vault` | base64, 17 B–4 MiB decoded |
| `vaultiv` | base64, 12 B |
| `version` | integer, 1–2,147,483,646 |

`crypto_version`, `vault_key_wrap`, and `vault_key_wrap_iv` are **not accepted**
(`deny_unknown_fields`). A vault whose stored `crypto_version` is not 2 returns
`409 UNSUPPORTED_CRYPTO_VERSION`.

### `POST /api/vault/password` (session)

| Field | Shape |
|---|---|
| `new_vault_verifier` | base64, 32 B |
| `new_salt` | must be absent — `409 PASSWORD_CHANGE_REQUIRES_REWRAP` |
| `new_iterations` | must be absent — `409 PASSWORD_CHANGE_REQUIRES_REWRAP` |

The atomic rewrap (new envelope + `credential_version` CAS) is the P1
password-change item.

### Recovery

`/api/recovery/challenge`: `vault_id` canonical v4.
`/api/recovery/unlock`: `vault_id` canonical v4 (400); `selector` canonical
UUID and `proof` exact 32 B, both on the uniform `401 AUTH_FAILED` path.
`/api/recovery/rewrap`: `vault_id`, `selector` (401), `proof` 32 B (400),
`credential_version >= 0`, `new_salt` 16 B, `new_iterations` bounded,
`new_vault_verifier` 32 B, `new_vault_key_wrap` 48 B, `new_vault_key_wrap_iv` 12 B.
`/api/recovery/regenerate`: `vault_id` canonical and equal to session,
`selector` (401), `proof` 32 B, `new_recovery_verifier` 32 B,
`new_recovery_salt` 16 B, `new_recovery_wrap` 48 B, `new_recovery_wrap_iv` 12 B.

The selector pre-check deliberately returns the **same** 401 as a wrong proof —
a shape failure must not become an oracle.

### Ciphertext-carrying cloud writes (session)

`/api/cloud/vaults/create|replace`: `vault_id` canonical and equal to the
session; `package` encoded ≤ 8,388,608 chars and ≤ 6 MiB decoded, with a valid
package header; `file_id` / `if_match_revision` ≤ 512 chars.
`/api/cloud/vaults/delete`, `/api/cloud/binding`: identifiers ≤ 512 chars,
`vault_id` canonical and equal to the session.

## Base64 length cheat sheet

| Bytes | Canonical base64 chars |
|---|---|
| 12 | 16 |
| 16 | 24 |
| 32 | 44 |
| 48 | 64 |

A fresh vault row, checked by hand:

```sh
sqlite3 ~/Library/Application\ Support/Voult/voult.db \
  "select length(salt), length(vaultiv), length(vault_verifier),
          length(vault_key_wrap), length(vault_key_wrap_iv),
          length(recovery_verifier), length(recovery_salt),
          length(recovery_wrap), length(recovery_wrap_iv),
          crypto_version, iterations from vault"
# → 24|16|44|64|16|44|24|64|16|2|60000
```
