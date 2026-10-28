#!/usr/bin/env bash
# Link gitignored .env files from the main worktree into linked git worktrees.
#
# Git never copies ignored files into a new worktree, and it has no
# "worktree created" hook. The only native event that fires during
# `git worktree add` is post-checkout, so .githooks/post-checkout calls this
# script. The script discovers the canonical env files in the main worktree
# (the first entry from `git worktree list --porcelain`) and symlinks the
# missing ones into the target. Existing files are never overwritten.
#
# Usage:
#   scripts/env-worktrees.sh setup       # one-time per clone; installs the hook + backfills
#   scripts/env-worktrees.sh sync        # current worktree
#   scripts/env-worktrees.sh sync --all  # every linked worktree (repair/bypass cases)

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/env-worktrees.sh setup
      One-time per clone: sets core.hooksPath=.githooks and links env files
      into every existing linked worktree.

  scripts/env-worktrees.sh sync [--all] [--quiet]
      Links missing env files into the current worktree, or every linked
      worktree with --all. Safe to rerun; never overwrites an existing file.
EOF
}

say() {
  [ "${QUIET:-0}" -eq 1 ] || printf '%s\n' "$*"
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# Prefer the worktree the caller is in (the hook always runs with its cwd set
# to the new worktree). Fall back to the repository containing this script so
# the script also works when invoked from outside a checkout.
CURRENT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$CURRENT_ROOT" ]; then
  CURRENT_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)
fi
[ -n "$CURRENT_ROOT" ] || { echo "error: not inside a Git worktree" >&2; exit 1; }

# The first worktree in porcelain output is always the main worktree. Its
# ignored .env files are the source of truth for every linked worktree.
MAIN_ROOT=$(git -C "$CURRENT_ROOT" worktree list --porcelain | sed -n '1s/^worktree //p')
[ -n "$MAIN_ROOT" ] || { echo "error: could not determine the main worktree" >&2; exit 1; }

# Discover only ignored env files. If a file is not ignored it must not be
# linked: the link would otherwise be untracked and could be committed.
env_files() {
  git -C "$MAIN_ROOT" ls-files -z --others --ignored --exclude-standard -- \
    '.env' '.env.*' ':(glob)**/.env' ':(glob)**/.env.*'
}

sync_one() {
  target=$1

  # Running in the main worktree is a no-op: the sources already live there.
  [ "$target" = "$MAIN_ROOT" ] && return 0

  if [ ! -d "$target" ]; then
    warn "worktree directory is missing: $target"
    return 0
  fi

  linked=0
  present=0

  while IFS= read -r -d '' rel; do
    base=${rel##*/}

    # Templates are checked-in examples, not secrets.
    case "$base" in
      *.example|*.sample|*.template|*.dist) continue ;;
    esac

    # Skip files that are ignored only because an ancestor directory is
    # ignored (build output, node_modules, ...). They are artifacts, not the
    # developer's canonical env files.
    parent=${rel%/*}
    if [ "$parent" != "$rel" ] && git -C "$MAIN_ROOT" check-ignore -q -- "$parent/"; then
      continue
    fi

    src="$MAIN_ROOT/$rel"
    if [ ! -e "$src" ] && [ ! -L "$src" ]; then
      warn "source disappeared while linking: $src"
      continue
    fi

    dest="$target/$rel"
    if [ -L "$dest" ] || [ -e "$dest" ]; then
      if [ -e "$dest" ] && [ "$dest" -ef "$src" ]; then
        present=$((present + 1))
      else
        say "kept existing $dest (not overwriting)"
      fi
      continue
    fi

    # Belt and braces: never create a link at a path Git tracks or would stage.
    if git -C "$target" ls-files --error-unmatch -- "$rel" >/dev/null 2>&1; then
      warn "refusing to link $rel in $target: path is tracked by Git"
      continue
    fi
    if ! git -C "$target" check-ignore -q -- "$rel"; then
      warn "refusing to link $rel in $target: path is not gitignored there"
      continue
    fi

    mkdir -p -- "$(dirname -- "$dest")"
    ln -s -- "$src" "$dest"
    say "linked $rel -> $src"
    linked=$((linked + 1))
  done < <(env_files)

  if [ "$linked" -gt 0 ]; then
    say "linked $linked env file(s) into $target"
  elif [ "$present" -eq 0 ]; then
    say "no env files to link for $target"
  fi
}

sync_all() {
  while IFS= read -r wt; do
    [ "$wt" = "$MAIN_ROOT" ] && continue
    sync_one "$wt"
  done < <(git -C "$CURRENT_ROOT" worktree list --porcelain | sed -n 's/^worktree //p')
}

setup() {
  hooks_path=$(git -C "$CURRENT_ROOT" config --local --get core.hooksPath || true)

  if [ -n "$hooks_path" ] && [ "$hooks_path" != ".githooks" ]; then
    echo "error: core.hooksPath is already set to '$hooks_path'." >&2
    echo "       Merge .githooks/post-checkout into that directory, or set" >&2
    echo "       core.hooksPath=.githooks manually, then rerun this command." >&2
    exit 1
  fi

  if [ "$hooks_path" != ".githooks" ]; then
    git -C "$CURRENT_ROOT" config --local core.hooksPath .githooks
    say "set core.hooksPath=.githooks"
  else
    say "core.hooksPath is already .githooks"
  fi

  # Keep the checked-in modes executable even if the clone lost them.
  chmod +x "$SCRIPT_DIR/env-worktrees.sh" "$MAIN_ROOT/.githooks/post-checkout"

  # New worktrees only receive the hook if it is committed. This mainly
  # catches someone running setup before committing the hook files.
  for file in .githooks/post-checkout scripts/env-worktrees.sh; do
    git -C "$CURRENT_ROOT" ls-files --error-unmatch -- "$file" >/dev/null 2>&1 ||
      warn "$file is not tracked; commit it so new worktrees contain the hook"
  done

  sync_all
}

COMMAND=${1:-sync}
shift || true

case "$COMMAND" in
  sync)
    ALL=0
    QUIET=0
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --all) ALL=1 ;;
        --quiet|-q) QUIET=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
      shift
    done
    if [ "$ALL" -eq 1 ]; then
      sync_all
    else
      sync_one "$CURRENT_ROOT"
    fi
    ;;
  setup)
    [ "$#" -eq 0 ] || { echo "error: setup takes no options" >&2; exit 2; }
    setup
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "error: unknown command: $COMMAND" >&2
    usage >&2
    exit 2
    ;;
esac
