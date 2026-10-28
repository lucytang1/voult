import type { CloudBinding, MirrorResult } from "./api";
import { providerLabelForKind } from "./providers";

/**
 * What Settings says about the backup, derived from what the server actually
 * recorded.
 *
 * Two rules shape everything here:
 *
 *  1. **No engineering telemetry in the primary line.** Vault versions, provider
 *     revisions and file ids do not help anyone decide anything, so they live in
 *     the collapsed "technical details" block. A user reads a sentence and a
 *     timestamp.
 *  2. **Never claim a state the server has not confirmed.** The mirror runs
 *     detached, so `saving` is only shown while the binding says work is owed (or
 *     an action in this pane is in flight). Once nothing is owed, the settled
 *     truth wins — including "paused", "missing" and "conflict", which are states
 *     of the *remote copy* and must not be softened into "backing up".
 *
 * Pure functions, no React, so the copy is reviewable in one place and testable
 * independently of the screen.
 */

export type BackupTone = "ok" | "warn" | "error" | "neutral";

export type BackupPhase =
  | "loading"
  | "none"
  | "saving"
  | "current"
  | "stalled"
  | "paused"
  | "missing"
  | "conflict"
  | "failed";

/** What the pane should offer. `null` means "nothing to do right now". */
export type BackupAction = "backup-now" | "retry" | "reconnect" | "recreate" | "replace";

export interface BackupView {
  phase: BackupPhase;
  tone: BackupTone;
  headline: string;
  detail: string;
  action: BackupAction | null;
}

export interface MirrorFeedback {
  text: string;
  tone: BackupTone;
}

/** Headline colour per tone. */
export const BACKUP_TONE_COLOR: Record<BackupTone, string> = {
  ok: "#4ade80",
  warn: "#fbbf24",
  error: "#f87171",
  neutral: "#a1a1aa",
};

/** Tailwind class for the small status dot. */
export const BACKUP_DOT: Record<BackupTone, string> = {
  ok: "bg-green-500",
  warn: "bg-yellow-500",
  error: "bg-red-500",
  neutral: "bg-zinc-500",
};

/**
 * How long a transient state may last before the pane stops pretending it is
 * nearly done. Derived from the server's own bounds: the sweeper runs every 60 s
 * and a provider request is capped at 30 s, so beyond 90 s no progress is being
 * made by anyone.
 */
export const STALL_AFTER_MS = 90_000;

/**
 * True while the server owes the provider copy a write, or is writing one.
 *
 * This is the pane's definition of "a backup is running": it disables provider
 * switching, because the server refuses one mid-pass anyway and a disabled
 * control with a visible reason is better than a request that comes back 409.
 *
 * `idle` with writes still owed is included because `mark_pending` runs after the
 * commit: there is a short window where a write is queued but the status has not
 * been opened yet. Every *other* status — `conflict`, `auth_required`,
 * `unlinked`, `error` — describes the remote copy rather than work in flight, so
 * blocking a switch there would trap the user in the one state where switching is
 * the fix.
 */
export function isBackupInFlight(binding: CloudBinding | null | undefined): boolean {
  if (!binding) return false;
  if (binding.sync_status === "pending" || binding.sync_status === "mirroring") return true;
  if (binding.sync_status === "idle") return (binding.versions_behind ?? 0) > 0;
  return false;
}

export interface DescribeBackupInput {
  /** The binding, `null` for "no backup configured", `undefined` while loading. */
  binding: CloudBinding | null | undefined;
  /** Whether this vault still holds a credential for the bound provider. */
  hasCredential: boolean;
  providerKind?: string;
  loading: boolean;
  /** True while this pane is awaiting a manual backup it just started. */
  localSaving?: boolean;
  /** Injected so the function stays deterministic. */
  now: number;
}

export function describeBackup(input: DescribeBackupInput): BackupView {
  const { binding, hasCredential, providerKind, loading, localSaving, now } = input;

  if (loading) {
    return {
      phase: "loading",
      tone: "neutral",
      headline: "Checking backup…",
      detail: "",
      action: null,
    };
  }
  if (binding === undefined || binding === null || !binding.remote_file_id) {
    return { phase: "none", tone: "neutral", headline: "", detail: "", action: null };
  }

  const provider = providerKind ? providerLabelForKind(providerKind) : "your provider";
  const status = binding.sync_status;

  // States of the remote copy come first: they each have a specific explanation
  // and none of them may be softened into "backing up".
  if (!hasCredential || status === "auth_required") {
    return {
      phase: "paused",
      tone: "warn",
      headline: "Backup paused",
      detail: `Voult no longer has access to ${provider}. Reconnect to resume backups.`,
      action: "reconnect",
    };
  }
  if (status === "conflict") {
    return {
      phase: "conflict",
      tone: "error",
      headline: "Backup not overwritten",
      detail: `${provider} has a copy Voult did not write. Your vault on this device is unaffected.`,
      action: "replace",
    };
  }
  if (status === "unlinked") {
    const removed =
      binding.last_mirror_error === "REMOTE_DELETED" ||
      binding.last_mirror_error === "VAULT_NOT_FOUND";
    return {
      phase: "missing",
      tone: "warn",
      headline: "Backup file missing",
      detail: removed
        ? `The backup file was removed from ${provider}. Your vault on this device is unaffected.`
        : `This vault is no longer linked to a file in ${provider}.`,
      action: "recreate",
    };
  }
  if (status === "error") {
    return {
      phase: "failed",
      tone: "error",
      headline: "Last backup didn't finish",
      detail: "Voult retries on the next change to this vault.",
      action: "retry",
    };
  }

  // A manual backup this pane started is also "in flight", even though the
  // server has not necessarily recorded it yet. Showing the previous
  // "Backed up" while the button says "Backing up…" would contradict itself.
  const transient = isBackupInFlight(binding);
  // The staleness check only reads the binding, so it is skipped while we are
  // waiting on our own new request — otherwise a current binding with an old
  // timestamp would look "stalled" the instant the button is pressed.
  if (transient && binding && !localSaving && isStale(binding, now)) {
    return {
      phase: "stalled",
      tone: "warn",
      headline: "Still backing up…",
      detail: "This is taking longer than usual. Voult keeps retrying.",
      action: "retry",
    };
  }
  if (localSaving || transient) {
    return {
      phase: "saving",
      tone: "warn",
      headline: "Saving changes…",
      detail: "Your vault is safe here. The cloud copy catches up in a moment.",
      action: null,
    };
  }

  return {
    phase: "current",
    tone: "ok",
    headline: "Backed up",
    detail: binding.last_mirrored_at
      ? `Last backup ${formatRelativeTime(binding.last_mirrored_at, now)}.`
      : "Your vault and its cloud copy match.",
    action: "backup-now",
  };
}

/** True when a transient status has outlived every server-side bound. */
function isStale(binding: CloudBinding, now: number): boolean {
  const updated = Date.parse(binding.updated_at);
  if (Number.isNaN(updated)) return false;
  return now - updated > STALL_AFTER_MS;
}

/**
 * Turns a "Back up now" outcome into a sentence.
 *
 * The error *code* is deliberately absent: it belongs in technical details, and
 * "Backup didn't finish" is the only thing the user can act on. The one code the
 * UI explains is `MIRROR_BUSY`, because it means "try again" rather than "it
 * broke".
 */
export function describeMirrorResult(
  result: MirrorResult,
  providerKind?: string,
): MirrorFeedback {
  const provider = providerKind ? providerLabelForKind(providerKind) : "your provider";
  switch (result.result) {
    case "mirrored":
      return { text: "Backed up just now.", tone: "ok" };
    case "up_to_date":
      return { text: "Already up to date.", tone: "ok" };
    case "conflict":
      return {
        text: `The copy in ${provider} changed, so Voult left it alone rather than replace it.`,
        tone: "error",
      };
    case "auth_required":
      return { text: `Access to ${provider} expired. Reconnect to resume backups.`, tone: "error" };
    case "unlinked":
      return { text: `The backup file is missing from ${provider}.`, tone: "error" };
    case "unsupported":
      return { text: "This vault can't be backed up yet.", tone: "error" };
    default:
      if (result.code === "MIRROR_BUSY") {
        return { text: "A backup is still finishing. Try again in a moment.", tone: "warn" };
      }
      return { text: "Backup didn't finish. Voult will retry.", tone: "error" };
  }
}

/** Network/transport failures have no server code; show a stable sentence. */
export function describeMirrorNetworkFailure(): MirrorFeedback {
  return { text: "Backup didn't finish. Check your connection and try again.", tone: "error" };
}

/** Rows for the collapsed "technical details" block. */
export function technicalDetails(
  binding: CloudBinding | null | undefined,
): { label: string; value: string }[] {
  if (!binding) return [];
  const rows: { label: string; value: string | undefined | null }[] = [
    { label: "Provider file", value: binding.remote_file_id },
    { label: "Provider revision", value: binding.remote_revision?.slice(0, 8) },
    { label: "Vault version", value: String(binding.vault_version) },
    {
      label: "Backup version",
      value:
        binding.mirrored_vault_version === undefined || binding.mirrored_vault_version === null
          ? "never backed up"
          : String(binding.mirrored_vault_version),
    },
    { label: "Changes behind", value: String(binding.versions_behind ?? 0) },
    {
      label: "Last backup",
      value: binding.last_mirrored_at ? formatExactTime(binding.last_mirrored_at) : "never",
    },
    { label: "Last error", value: binding.last_mirror_error ?? "none" },
    { label: "Binding generation", value: String(binding.binding_generation) },
  ];
  return rows
    .filter((row): row is { label: string; value: string } => !!row.value)
    .map((row) => ({ label: row.label, value: row.value }));
}

/**
 * "just now" / "2 minutes ago" / "yesterday", for the one line a user reads.
 *
 * Falls back to a fixed phrase when `Intl.RelativeTimeFormat` is unavailable
 * rather than showing an ISO timestamp in the primary line.
 */
export function formatRelativeTime(iso: string, now: number): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "recently";

  const diffSeconds = Math.round((then - now) / 1000);
  const abs = Math.abs(diffSeconds);
  if (abs < 45) return "just now";

  const rtf =
    typeof Intl !== "undefined" && "RelativeTimeFormat" in Intl
      ? new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })
      : null;

  if (abs < 3600) {
    const minutes = Math.round(diffSeconds / 60);
    return rtf ? rtf.format(minutes, "minute") : `${Math.abs(minutes)} minutes ago`;
  }
  if (abs < 86_400) {
    const hours = Math.round(diffSeconds / 3600);
    return rtf ? rtf.format(hours, "hour") : `${Math.abs(hours)} hours ago`;
  }
  const days = Math.round(diffSeconds / 86_400);
  return rtf ? rtf.format(days, "day") : `${Math.abs(days)} days ago`;
}

function formatExactTime(iso: string): string {
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) return iso;
  return new Date(parsed).toLocaleString();
}
