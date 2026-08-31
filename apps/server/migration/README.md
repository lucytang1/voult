# Running Migrator CLI

- Generate a new migration file
    ```sh
    cargo run -- generate MIGRATION_NAME
    ```
- Apply all pending migrations
    ```sh
    cargo run
    ```
    ```sh
    cargo run -- up
    ```
- Apply first 10 pending migrations
    ```sh
    cargo run -- up -n 10
    ```
- Rollback last applied migrations
    ```sh
    cargo run -- down
    ```
- Rollback last 10 applied migrations
    ```sh
    cargo run -- down -n 10
    ```
- Drop all tables from the database, then reapply all migrations
    ```sh
    cargo run -- fresh
    ```
- Rollback all applied migrations, then reapply all migrations
    ```sh
    cargo run -- refresh
    ```
- Rollback all applied migrations
    ```sh
    cargo run -- reset
    ```
- Check the status of all migrations
    ```sh
    cargo run -- status
    ```

## Clean-start schema (vault-centric)

The migration set is a single initial migration that creates the vault-centric
schema: `vault` (primary identity, with `vault_verifier`), `session` (keyed by
`vault_id`), and the Google/cloud tables all keyed by `vault_id`. There is **no
`user`, `user_key`, or `user_vault` table** — the vault is the only identity and
authorization boundary.

This is a deliberate breaking change. The old migration history has been
removed, so an existing development database (`apps/server/voult.db`) is
intentionally incompatible and must be deleted and recreated:

```sh
rm apps/server/voult.db
# The server runs Migrator::up automatically on startup.
cargo run
```
