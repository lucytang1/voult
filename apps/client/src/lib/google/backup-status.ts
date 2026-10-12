import type { GoogleBinding, MirrorResult } from "./api";

/**
 * Turns real Drive backup state into what the user is actually told.
 *
 * This replaced a constant "Encrypted sync enabled" label that was true the
 * moment OAuth completed and stayed true while the Drive copy silently went
 * stale — the exact failure the roadmap item describes. Everything here is
 * derived from `cloud_binding`: whether the vault has writes the backup is
 * missing, and why a mirror failed when one did.
 *
 * Pure functions, no React, so the display logic is unit-testable independently
 * of the screen.
 */

export type Tone = "ok" | "warn" | "error";

export interface BackupView {
  /** Tailwind class for the status dot. */
  dot: string;
  title: string;
  detail: string;
  tone: Tone;
}

export interface MirrorFeedback {
  text: string;
  tone: Tone;
}

export const BACKUP_TITLE_COLOR: Record<Tone, string> = {
  ok: "#4ade80",
  warn: "#fbbf24",
  error: "#f87171",
};

export function describeBackup(binding: GoogleBinding): BackupView {
  const behind = binding.versions_behind ?? 0;
  const status = binding.sync_status;

  // Error and conflict states come first: they explain a stale or diverged
  // backup that a softer "pending" label would otherwise paper over.
  if (status === "conflict") {
    return {
      dot: "bg-red-500",
      tone: "error",
      title: "Backup conflict",
      detail:
        "The copy in Google Drive changed since the last backup, so it was left alone rather than overwritten. Your vault on this device is unaffected.",
    };
  }
  if (status === "auth_required") {
    return {
      dot: "bg-red-500",
      tone: "error",
      title: "Backup paused",
      detail: "Google access expired. Reconnect to resume backing up this vault.",
    };
  }
  if (status === "unlinked") {
    const missing =
      binding.last_mirror_error === "REMOTE_DELETED" ||
      binding.last_mirror_error === "VAULT_NOT_FOUND";
    return {
      dot: "bg-yellow-500",
      tone: "warn",
      title: "Backup unavailable",
      detail: missing
        ? "The backup file is missing from Google Drive. Your vault on this device is unaffected."
        : "This vault is not linked to a Google Drive file.",
    };
  }
  if (status === "error") {
    return {
      dot: "bg-red-500",
      tone: "error",
      title: "Last backup failed",
      detail: `${binding.last_mirror_error ?? "PROVIDER_ERROR"} — this will retry on the next vault change. Your vault on this device is unaffected.`,
    };
  }
  if (behind > 0 || status === "pending" || status === "mirroring") {
    return {
      dot: "bg-yellow-500",
      tone: "warn",
      title:
        status === "mirroring"
          ? "Backing up…"
          : `Backup is ${behind} ${behind === 1 ? "change" : "changes"} behind`,
      detail: `Vault version ${binding.vault_version} on this device; Drive holds version ${
        binding.mirrored_vault_version ?? "none"
      }.`,
    };
  }
  return {
    dot: "bg-green-500",
    tone: "ok",
    title: "Backup up to date",
    detail: binding.last_mirrored_at
      ? `Vault version ${binding.vault_version} · last backed up ${new Date(
          binding.last_mirrored_at
        ).toLocaleString()}`
      : `Vault version ${binding.vault_version} · backed up`,
  };
}

/** Shown before the binding has loaded. Deliberately not "up to date". */
export function describeBackupLoading(): BackupView {
  return {
    dot: "bg-yellow-500",
    tone: "warn",
    title: "Checking backup status…",
    detail: "",
  };
}

/**
 * Turns a mirror result into a sentence. Failure codes are shown verbatim so
 * the user can report something specific rather than "sync failed".
 */
export function describeMirrorResult(result: MirrorResult): MirrorFeedback {
  switch (result.result) {
    case "mirrored":
      return { text: `Backed up vault version ${result.vault_version}.`, tone: "ok" };
    case "up_to_date":
      return {
        text: `Already up to date at vault version ${result.vault_version}.`,
        tone: "ok",
      };
    case "conflict":
      return {
        text: "The Drive copy changed since the last backup and was not overwritten.",
        tone: "error",
      };
    case "auth_required":
      return {
        text: "Google access expired. Reconnect to resume backing up.",
        tone: "error",
      };
    case "unlinked":
      return { text: "This vault is not linked to a Google Drive file.", tone: "error" };
    case "unsupported":
      return {
        text: `This vault cannot be backed up yet (${result.reason}).`,
        tone: "error",
      };
    default:
      return {
        text: `Backup failed (${result.code}). Will retry on the next change.`,
        tone: "error",
      };
  }
}

/** Network/transport failures have no server code; show a stable label instead. */
export function describeMirrorNetworkFailure(code?: string): MirrorFeedback {
  return { text: `Backup failed (${code ?? "NETWORK_ERROR"}).`, tone: "error" };
}
