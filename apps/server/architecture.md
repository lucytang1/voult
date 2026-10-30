# Server architecture

The vault is the server-side identity and authorization boundary. The server
never receives a master password, plaintext vault, vault key, or derived key.

## Core API contracts

`POST /register` accepts a client-generated `vault_id`, ciphertext snapshot,
KDF metadata, `vault_verifier`, and optional password-wrapped vault-key
envelope. It creates the vault and establishes its session.

`vault_verifier` crosses the wire but is **never stored**: the row keeps
`verifier_salt` + `verifier_hash`, where
`verifier_hash = HMAC-SHA256(verifier_salt, "voult-verifier-v1|" + presented)`
(`src/credentials.rs`, migration `m20261028_000008`). Storing the value verbatim
made one row a replayable login credential. The check is constant-time, and the
stored hash is never accepted as input — the client always sends the preimage.

`POST /auth` accepts `{ vault_id, vault_verifier }`. On success it establishes
a session and returns only the vault's KDF, crypto-version, and encrypted
key-envelope metadata needed for client-side unlock.

`GET /session` returns `{ authenticated, vault_id, crypto_version }` after
validating that the session vault still exists.

`GET /get_vault` and `POST /update_vault` derive the vault exclusively from the
authenticated session. Updates use ciphertext-only version compare-and-swap.

`POST /logout` purges the current session. Google OAuth state, tokens, cloud
bindings, and Drive operations are likewise scoped to the authenticated
`vault_id`; provider account/email values are metadata only.

## Logging

All server logging goes through the shared `crates/logger` crate: the default
`logger` instance or `Logger::create(context)`. `VOULT_LOG_LEVEL`
(`debug|log|warn|error`, default `log`) is the single minimum level. Lines are
written to stderr with a hardcoded context and an ISO 8601 UTC timestamp.

`logger::init()` installs the crate as the global `log` backend. Actix request
logs, SeaORM/SQLx records, and the `migration` crate therefore use the same
filter and formatter; `RUST_LOG` is ignored. Target-specific formatters clean up
noisy dependency records: `sqlx::query` uses the SQL summary as the message and
`rows_affected`/`rows_returned`/`elapsed`/`slow_threshold` as metadata, while
`actix_web::middleware::logger` uses `METHOD PATH STATUS` as the message and
connection/request details as metadata.

## Database model

The clean-start migration creates `vault`, `session`, `google_token`,
`cloud_binding`, `oauth_state`, and pending Google-token tables. There are no
account or ownership-join tables. Existing development databases are
intentionally incompatible and must be deleted and recreated before starting
the server.
