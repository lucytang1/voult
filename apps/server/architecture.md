# Server architecture

The vault is the server-side identity and authorization boundary. The server
never receives a master password, plaintext vault, vault key, or derived key.

## Core API contracts

`POST /register` accepts a client-generated `vault_id`, ciphertext snapshot,
KDF metadata, `vault_verifier`, and optional password-wrapped vault-key
envelope. It creates the vault and establishes its session.

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

## Database model

The clean-start migration creates `vault`, `session`, `google_token`,
`cloud_binding`, `oauth_state`, and pending Google-token tables. There are no
account or ownership-join tables. Existing development databases are
intentionally incompatible and must be deleted and recreated before starting
the server.
