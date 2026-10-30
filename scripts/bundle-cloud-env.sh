#!/usr/bin/env bash
set -euo pipefail

# Bundle cloud-provider OAuth configuration into a built Voult.app.
#
# The server loads `Resources/.env` and `Resources/cloud.env` at startup
# (apps/server/src/config.rs:120 load_bundled_env), so whatever this script
# writes is the config a tester's install runs with. Only provider keys are
# written: DATABASE_URL, SESSION_COOKIE_KEY and friends stay out, so the
# per-install defaults in config.rs still win.
#
# Sources, in order of precedence:
#   1. apps/server/.env      — local release builds
#   2. the process env       — GitHub Actions secrets on CI
#
# Each provider is resolved INDEPENDENTLY. Dropbox is bundled whenever its id
# and secret exist, whether or not Google is configured, and vice versa; the
# old Google-only logic silently dropped DROPBOX_* from the bundle.
#
# A provider is "configured" (see providers/*/config.rs) only when BOTH
# CLIENT_ID and CLIENT_SECRET are present. Half-configured providers are
# dropped rather than shipped, because the app would otherwise advertise a
# provider whose OAuth can never complete.
#
# Usage: ./scripts/bundle-cloud-env.sh <path-to-Contents/Resources>

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-}"
if [[ -z "$DEST" ]]; then
  echo "usage: $0 <path-to-Contents/Resources>" >&2
  exit 2
fi
mkdir -p "$DEST"

OUT="$DEST/cloud.env"
rm -f "$OUT" "$DEST/google.env" "$DEST/.env"

# --- 1. Local checkout values -------------------------------------------------
if [[ -f "$ROOT/apps/server/.env" ]]; then
  echo "Reading cloud OAuth config from apps/server/.env"
  grep -E '^(GOOGLE_|DROPBOX_|CORS_ORIGINS=)' "$ROOT/apps/server/.env" > "$OUT" || true
fi
touch "$OUT"

# --- 2. Environment (CI secrets) ----------------------------------------------
# Append a key only when it is non-empty and not already provided by the file,
# so a local .env always wins over the ambient environment.
set_if_missing() {
  local key="$1" value="${2:-}"
  [[ -z "$value" ]] && return 0
  grep -q "^${key}=" "$OUT" && return 0
  printf '%s=%s\n' "$key" "$value" >> "$OUT"
}

set_if_missing CORS_ORIGINS "${CORS_ORIGINS:-}"

set_if_missing GOOGLE_CLIENT_ID "${GOOGLE_CLIENT_ID:-}"
set_if_missing GOOGLE_CLIENT_SECRET "${GOOGLE_CLIENT_SECRET:-}"
set_if_missing GOOGLE_OAUTH_REDIRECT_URI "${GOOGLE_OAUTH_REDIRECT_URI:-}"
set_if_missing GOOGLE_DRIVE_SCOPE "${GOOGLE_DRIVE_SCOPE:-}"
set_if_missing GOOGLE_POST_AUTH_REDIRECT "${GOOGLE_POST_AUTH_REDIRECT:-}"

set_if_missing DROPBOX_CLIENT_ID "${DROPBOX_CLIENT_ID:-}"
set_if_missing DROPBOX_CLIENT_SECRET "${DROPBOX_CLIENT_SECRET:-}"
set_if_missing DROPBOX_OAUTH_REDIRECT_URI "${DROPBOX_OAUTH_REDIRECT_URI:-}"
set_if_missing DROPBOX_POST_AUTH_REDIRECT "${DROPBOX_POST_AUTH_REDIRECT:-}"

env_get() { grep -m1 "^$1=" "$OUT" 2>/dev/null | cut -d= -f2- || true; }
env_drop() {
  { grep -v "^$1=" "$OUT" || true; } > "$OUT.tmp"
  mv "$OUT.tmp" "$OUT"
}

CONFIGURED=0

# Validate one provider and fill its callback default when it was not supplied.
# The server registers exactly one callback route — /api/cloud/oauth/callback —
# with the provider selected by the `provider` query parameter, so that is the
# only correct default. (The old script injected /api/google/oauth/callback,
# a route that no longer exists.)
finalize_provider() {
  local label="$1" prefix="$2" kind="$3"
  local id secret
  id="$(env_get "${prefix}CLIENT_ID")"
  secret="$(env_get "${prefix}CLIENT_SECRET")"

  if [[ -z "$id" || -z "$secret" ]]; then
    if [[ -n "$id" || -n "$secret" ]]; then
      echo "WARNING: ${label} is half-configured — ${prefix}CLIENT_ID and ${prefix}CLIENT_SECRET must both be set; dropping it" >&2
    fi
    env_drop "${prefix}CLIENT_ID"
    env_drop "${prefix}CLIENT_SECRET"
    env_drop "${prefix}OAUTH_REDIRECT_URI"
    env_drop "${prefix}POST_AUTH_REDIRECT"
    return 0
  fi

  set_if_missing "${prefix}OAUTH_REDIRECT_URI" \
    "http://localhost:8080/api/cloud/oauth/callback?provider=${kind}"
  echo "Bundled ${label} OAuth config"
  CONFIGURED=$((CONFIGURED + 1))
}

finalize_provider "Google Drive" "GOOGLE_" "google_drive"
finalize_provider "Dropbox" "DROPBOX_" "dropbox"

# The server still accepts the legacy GOOGLE_REDIRECT_URI alias
# (providers/google_drive/config.rs:17), but the only callback route it
# registers is /api/cloud/oauth/callback. A legacy value in a shipped bundle
# can therefore only be stale — the old release script wrote
# /api/google/oauth/callback, which no longer exists — so drop the alias and
# keep the canonical key written above.
env_drop GOOGLE_REDIRECT_URI

# --- 3. Write the result ------------------------------------------------------
if [[ "$CONFIGURED" -eq 0 ]]; then
  echo "WARNING: no cloud provider configured — set GOOGLE_CLIENT_ID/SECRET and/or DROPBOX_CLIENT_ID/SECRET in apps/server/.env or as secrets; cloud backup will report every provider as unavailable" >&2
fi

if [[ -s "$OUT" ]]; then
  # The server checks Resources/.env first, then Resources/cloud.env; write the
  # same content to both so either lookup path yields the bundled config.
  cp "$OUT" "$DEST/.env"
  echo "Bundled Resources/cloud.env (also copied to Resources/.env):"
  sed -E 's/(SECRET=).*/\1***redacted***/' "$OUT"
else
  rm -f "$OUT" "$DEST/.env"
fi
