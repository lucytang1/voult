# `logger`

Small shared logger for the Voult server and launcher.

It exposes a default `logger` instance and `Logger::create(context)` for typed
app contexts. Every log call takes exactly two arguments: a message and
metadata. The API is modelled on Bluesky's logger, without Sentry support and
without its Sentry-specific metadata fields.

## Usage

```rust
use logger::{logger, LauncherContext, Logger, Metadata, MetaValue};

// Default context ("logger")
logger.log("Starting server", Metadata::new());

// Typed launcher context
let process = Logger::create(LauncherContext::Process);
process.error(&err, Metadata::new());

// Typed server context
let recovery = Logger::create(logger::ServerContext::Recovery);
recovery.warn("recovery challenge rejected", Metadata::new());

// Metadata
logger.warn(
    "vault conflict",
    logger::metadata! {
        "vault_id" => vault_id.to_string(),
        "status" => 409,
        "retryable" => false,
    },
);

// Error and unknown metadata arms
logger.error(
    &err,
    logger::metadata! {
        "pid" => pid,
        "cause" => MetaValue::error(&err),
        "raw" => MetaValue::unknown(&raw_status),
    },
);
```

`Logger` is a cheap `Copy` value. Creating one does not register anything; the
level filter is global. `Logger::create` is `const`, so a module can define:

```rust
use logger::{LauncherContext, ServerContext};

const SERVER_LOG: logger::ServerLogger =
    logger::Logger::create(ServerContext::Server);
const PROCESS_LOG: logger::LauncherLogger =
    logger::Logger::create(LauncherContext::Process);
```

`error` accepts a string or any error type because both implement `Display`.

## Context types

There are two app context types, both hardcoded:

- `ServerContext` — `Server`, `Config`, `Auth`, `Vault`, `Vaults`, `Register`,
  `Lock`, `Pair`, `Session`, `Recovery`, `Favicon`, `Cloud`, `Migration`
- `LauncherContext` — `Launcher`, `Config`, `Process`, `Tray`

`ServerLogger` / `LauncherLogger` are type aliases for
`Logger<ServerContext>` / `Logger<LauncherContext>`. Dependency records that
arrive through the `log` facade use their `log` target as the context, because
they cannot supply a typed first-party context.

## Levels and filtering

| Level | Use |
|---|---|
| `debug` | Development-only detail |
| `log` | Production breadcrumbs |
| `warn` | Recoverable problems worth attention |
| `error` | Failures |

`VOULT_LOG_LEVEL` is the minimum printed level:

| `VOULT_LOG_LEVEL` | Printed |
|---|---|
| `debug` | `DEBUG`, `LOG`, `WARN`, `ERROR` |
| `log` (default) | `LOG`, `WARN`, `ERROR` |
| `warn` | `WARN`, `ERROR` |
| `error` | `ERROR` |
| `info` | alias for `log` |

The value is case-insensitive and trimmed. Unset means `log`. A set-but-empty
or unrecognised value prints one warning and falls back to `log`.

Call `logger::init()` once after dotenv loading. It is idempotent and returns the
effective filter.

## Metadata

`Metadata` is an ordered map of `&'static str` keys to `MetaValue`:

| TypeScript shape | Rust |
|---|---|
| `Serializable` | `MetaValue::Json(serde_json::Value)` |
| `Error` | `MetaValue::Error(String)` |
| `unknown` | `MetaValue::Unknown(String)` (Debug text) |

`metadata! { ... }` accepts common serializable values directly (`&str`,
`String`, `bool`, numeric primitives, `serde_json::Value`). For anything else:

- `MetaValue::json(value)` uses `serde_json::to_value`.
- `MetaValue::error(&e)` stores the error's `Display` text.
- `MetaValue::unknown(&value)` stores the value's `Debug` text.

## Output

All levels go to stderr. Events without metadata occupy one line; metadata
expands into an indented block:

```text
2026-10-27T18:08:01+00:00 WARN  (config) VOULT_ENV is empty, defaulting to production {
  env_var: 'VOULT_ENV'
}
2026-10-27T18:08:01+00:00 ERROR (process) failed to spawn server {
  pid: 1234
}
```

Format:

```text
<timestamp> <LEVEL padded to 5> (<context>) <message>
{
  <key>: <value>,
  ...
}
```

- Timestamps are ISO 8601 UTC, e.g. `2026-10-28T04:05:23+00:00`.
- The metadata block is omitted when empty. Each field is two-space indented,
  with a comma between fields and none after the last.
- String/text values are single-quoted and escaped. Numbers, booleans, and null
  are bare; JSON arrays/objects render compactly.
- Colour is applied to the whole prefix (timestamp, level, and context), never
  to the message or metadata, and only when stderr is a TTY.
  `NO_COLOR` or `TERM=dumb` disables it.
- Write failures are ignored; logging never panics.

## Target-specific formatting

Noisy dependency targets are translated by `src/formatter/` before the generic
renderer runs. Unrecognised targets pass through unchanged.

### SQLx query records

SQLx emits query timing fields as one escaped `key=value` string. The backend
reformats `sqlx::query` records so the SQL summary is the message and the useful
counters are ordinary metadata. The full `db.statement` is omitted because it
duplicates the summary and is mostly escaped newlines.

```text
2026-10-28T03:28:55+00:00 LOG   (sqlx::query) SELECT "cloud_binding"."vault_id", … {
  rows_affected: 0,
  rows_returned: 1,
  elapsed: '718.25µs'
}
```

### Actix request records

The default Actix `Logger` middleware emits one space-separated line. It is
reformatted with the request and status as the message and connection details as
metadata:

```text
2026-10-28T04:05:23+00:00 LOG   (actix_web::middleware::logger) GET /api/get_vault 200 {
  remote: '::1',
  size: 1501,
  duration: '0.534ms',
  referer: 'http://localhost:8081/',
  user_agent: 'Mozilla/5.0 …'
}
```

`-` placeholders for referer, user-agent, or size are omitted.

## Global `log` backend

`init()` installs this crate as the global `log` backend. That makes Actix
request logs, SeaORM/SQLx records, and other dependency logs use the same
`VOULT_LOG_LEVEL` filter and output format. `log::Level::Info` is rendered as
`LOG`; `Debug`/`Trace` are rendered as `DEBUG`.

Only one global `log` backend can exist. If another backend was installed
first, `init()` prints a warning and leaves it in place; direct `logger` /
`Logger::create` calls still work. `RUST_LOG` is not read.

## Security

The logger does not redact anything. Never log master passwords, vault keys,
wrapped key envelopes, verifiers, recovery keys/proofs, session cookies, OAuth
codes/tokens, request bodies, or plaintext vault data. Metadata is not exempt.
Debug-level third-party logs may include SQL text and bound parameters; keep
production at `log`/`info`.

## Tests

```sh
cd crates/logger
cargo test
```
