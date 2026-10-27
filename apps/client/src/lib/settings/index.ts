/**
 * Client-side preferences — currently just the two autolock timers.
 *
 * These live in localStorage rather than the per-vault SQLite `client_state`
 * table for two reasons:
 *
 *  1. The autolock deadline has to be readable while the vault is *locked* —
 *     that is exactly the moment it matters (deciding whether a reload may
 *     auto-unlock). SQLite is only open while a vault is unlocked.
 *  2. They are device preferences, not vault data: they are not encrypted,
 *     not synced, and must survive a vault switch.
 *
 * Nothing here is secret. It describes UI behaviour only — never key material,
 * never a password, never the vault contents.
 */

/** Sentinel for "never lock automatically". */
export const AUTOLOCK_NEVER = 0;

// Keys are per-setting rather than one JSON blob so a single read/write never
// has to round-trip the other value (no read-modify-write race between tabs).
const WEB_KEY = "voult.autolock.webMinutes";
const EXTENSION_KEY = "voult.autolock.extensionMinutes";

/** Web default is deliberately longer than the extension's 5-minute default. */
export const DEFAULT_WEB_AUTOLOCK_MINUTES = 15;
/** Mirrors DEFAULT_LOCK_TIMEOUT_MINUTES in apps/extension/src/background/vault.ts. */
export const DEFAULT_EXTENSION_AUTOLOCK_MINUTES = 5;

/** Offered in Settings > Security > Autolock. */
export const AUTOLOCK_CHOICES: ReadonlyArray<{ label: string; minutes: number }> = [
  { label: "Never", minutes: AUTOLOCK_NEVER },
  { label: "1 min", minutes: 1 },
  { label: "5 min", minutes: 5 },
  { label: "10 min", minutes: 10 },
  { label: "15 min", minutes: 15 },
  { label: "30 min", minutes: 30 },
  { label: "1 hour", minutes: 60 },
];

/** Hard ceiling so a corrupt/hand-edited value can't disable autolock silently. */
const MAX_MINUTES = 240;

const readMinutes = (key: string, fallback: number): number => {
  if (typeof localStorage === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return fallback;
    const parsed = Number(raw);
    // Only "Never" (0) or a whole positive number of minutes is meaningful.
    if (!Number.isInteger(parsed) || parsed < 0) {
      console.warn(`Discarding invalid autolock value for ${key}`, raw);
      return fallback;
    }
    return Math.min(parsed, MAX_MINUTES);
  } catch (e) {
    console.warn("Failed to read autolock setting", e);
    return fallback;
  }
};

const writeMinutes = (key: string, minutes: number): void => {
  const clamped = Number.isFinite(minutes) ? Math.max(0, Math.min(Math.round(minutes), MAX_MINUTES)) : 0;
  try {
    localStorage.setItem(key, String(clamped));
  } catch (e) {
    console.warn("Failed to persist autolock setting", e);
  }
};

/** Inactivity timeout for the web app. `AUTOLOCK_NEVER` (0) disables it. */
export const getWebAutolockMinutes = (): number =>
  readMinutes(WEB_KEY, DEFAULT_WEB_AUTOLOCK_MINUTES);

export const setWebAutolockMinutes = (minutes: number): void => writeMinutes(WEB_KEY, minutes);

/**
 * Inactivity timeout the *extension* should use. Stored here so the preference
 * has one home, but NOT yet delivered to the extension — the extension still
 * reads its own `voult.lockTimeoutMinutes` in chrome.storage.local. Wiring the
 * two needs a server-side per-vault settings record the extension pulls on its
 * next session check; until then this value is the user's intent only.
 */
export const getExtensionAutolockMinutes = (): number =>
  readMinutes(EXTENSION_KEY, DEFAULT_EXTENSION_AUTOLOCK_MINUTES);

export const setExtensionAutolockMinutes = (minutes: number): void =>
  writeMinutes(EXTENSION_KEY, minutes);

/** "Never" / "15 minutes" — shared by both timers' UI and log lines. */
export function describeAutolock(minutes: number): string {
  if (minutes <= 0) return "Never";
  if (minutes === 60) return "1 hour";
  return minutes === 1 ? "1 minute" : `${minutes} minutes`;
}
