#!/usr/bin/env bash
#
# Tripwire for the P0 log-redaction rules (plans/p0-log-redaction.md).
#
# This is not a parser or a substitute for review: it catches the exact
# patterns this change removed, so reintroducing one fails loudly. It is
# intentionally dependency-free (grep only).
#
# Run from the repository root:
#   ./scripts/check-log-hygiene.sh

set -euo pipefail

fail=0

check() {
  local what=$1 pattern=$2
  shift 2
  if grep -REn "$pattern" "$@" >/dev/null 2>&1; then
    echo "FAIL: $what"
    grep -REn "$pattern" "$@"
    fail=1
  fi
}

# Actix's %r is the request line and includes the query; the default format
# also logs Referer and User-Agent. The server uses request_log.rs instead.
check "Actix default logger (its %r includes the query)" \
  'middleware::Logger' apps/server/src

# The provider account's email used to be logged and reflected in the OAuth
# redirect. It is not needed by the client and must not appear in a URL.
check "Email in an OAuth redirect or query" \
  'email=' apps/server/src apps/client/src

# Exchange failures used to append a free-form detail parameter to the
# redirect. Failures are fixed codes now.
check "OAuth error detail parameter" \
  'cloud_error_detail' apps/server/src apps/client/src

# reqwest's Display includes the URL, which is a site in the caller's vault.
# Favicon transport failures log the class, not the error text.
check "Favicon logs a reqwest error (its Display includes the URL)" \
  'favicon (fetch|read) failed: [{]e[}]' apps/server/src

if [ "$fail" -ne 0 ]; then
  echo
  echo "Log hygiene check failed. See plans/p0-log-redaction.md."
  exit 1
fi

echo "Log hygiene check passed."
