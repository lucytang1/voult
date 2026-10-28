import { useRouter } from "expo-router";
import { useEffect, useState } from "react";
import { Pressable, Text, View } from "react-native";
import { TextField } from "@/src/lib/components/text-field";
import {
  commitVaultUnlock,
  readLockRecordForSelection,
  selectVaultSession,
  updateDecryptedVault,
  updateLockEpoch,
  updateVaultVersion,
  useAppStore,
} from "@/src/lib/state";
import {
  unlockWithDevice,
  unlockWithPassword,
  reauthenticateAndUnlock,
} from "@/src/lib/auth/flows";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
import { fetchSession } from "@/src/lib/queries/session/query";
import { getDeviceEnvelope, getDeviceKey } from "@/src/lib/crypto/device-key";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { selectedVaultId } from "@/src/lib/state/vault-state";
import { displayVaultName } from "@/src/lib/vault/name";

/**
 * Lock screen: the selected vault's keys are absent. Unlock re-derives the
 * vault key locally from the master password. There is no logout — states are
 * locked / unlocked or no vault selected.
 *
 * M2: this screen now serves two situations that used to be conflated as
 * "not authenticated":
 *
 *  - The cookie is fine, the keys are gone (ordinary lock). Unlock is a purely
 *    local unwrap; a wrong password fails here at AES-GCM and nothing about the
 *    attempt leaves the device.
 *  - The cookie is gone (expired / rejected). The vault is still selected, and
 *    the same password field re-establishes the session via the existing
 *    verifier flow before unwrapping. `serverSession` decides which path runs.
 *
 * A vault the server no longer knows about is an availability error, not a
 * fourth state: we stay locked, keep the selection, and offer switch/create.
 *
 * Layout: the same two-panel frame as the landing page (`app/index.tsx`) —
 * wordmark on the left, an action card in the right rail. The card caps the
 * form at ~400px, so the password field and the button never stretch across a
 * wide display.
 */
export default function Lock() {
  // Only valid in the "locked" state; anything else bounces to its canonical page.
  useAuthGuard(["locked"]);
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const vaultId = selectedVaultId(useAppStore((s) => s.vault));
  const serverSession = useAppStore((s) => s.serverSession);
  const availability = useAppStore((s) => s.availability);

  // Why did we land here? Shown to the user and used to decide whether a
  // device unlock is acceptable. `null` means no lock record (e.g. the vault was
  // restored locked because the server cookie is missing or storage changed).
  const lockReason = readLockRecordForSelection()?.reason ?? null;

  // A dead cookie means the password has to do double duty: re-authenticate,
  // then unwrap. With a live session it is a local unwrap only. `unknown`
  // (offline / not probed) has no proven-bad cookie, so the local unwrap still
  // works when lock metadata is available.
  const needsReauth = serverSession !== "active";
  const sessionMissing = serverSession === "missing";
  const serverUnreachable = serverSession === "unknown";

  // Is there actually something to unwrap with? A device key without its
  // envelope cannot reopen anything, and offering the button would only produce
  // "Device unlock is unavailable" — the dead end that makes an unexpected lock
  // screen feel broken. Unknown until the local read resolves; assume "no".
  const [deviceMaterial, setDeviceMaterial] = useState(false);
  useEffect(() => {
    let active = true;
    if (!vaultId) {
      setDeviceMaterial(false);
      return;
    }
    (async () => {
      try {
        const key = await getDeviceKey(vaultId);
        const envelope = key ? await getDeviceEnvelope(vaultId) : null;
        if (active) {
          setDeviceMaterial(!!key && !!envelope && envelope.device_id === key.device_id);
        }
      } catch (e) {
        console.warn("Could not inspect local device material", e);
        if (active) setDeviceMaterial(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [vaultId]);

  // A timer lock is a convenience lock, not a deliberate "lock me out" decision.
  // Let the device key reopen it without retyping the master password, exactly
  // as a restart would. Manual/peer locks stay password-only.
  const canDeviceUnlock =
    deviceMaterial &&
    serverSession === "active" &&
    (lockReason === "autolock" || lockReason === null);

  const finishUnlock = async (unlocked: NonNullable<Awaited<ReturnType<typeof unlockWithDevice>>>) => {
    selectVaultSession(unlocked.session);
    commitVaultUnlock(unlocked.vaultKey);
    updateLockEpoch(unlocked.lockEpoch);
    updateDecryptedVault(unlocked.decryptedVault);
    updateVaultVersion(unlocked.version);
    await initSQLite(unlocked.session.vaultId);
  };

  const onDeviceUnlock = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const unlocked = await unlockWithDevice();
      if (!unlocked) {
        setError("Device unlock is unavailable — enter your master password.");
        return;
      }
      await finishUnlock(unlocked);
      router.replace("/home" as any);
    } catch (err) {
      console.warn("Device unlock failed", err);
      setError(err instanceof Error ? err.message : "Failed to unlock.");
    } finally {
      setSubmitting(false);
    }
  };
  const vaultUnavailable = availability === "unavailable";

  const onUnlock = async () => {
    if (!vaultId) return;
    setError(null);
    setSubmitting(true);
    try {
      if (needsReauth) {
        // Re-establishes the session with the existing verifier flow, then
        // unwraps locally. Sends only the verifier — never the password.
        await reauthenticateAndUnlock(password);
      } else {
        await unlockWithPassword(password);
      }

      // Reopen this vault's database (closed when it was locked) so
      // intents/sync can resume.
      await initSQLite(vaultId);
      // Converge to the current server epoch (a peer may have locked after
      // our lock metadata was captured). Best-effort: unlock stays valid.
      try {
        const remote = await fetchSession();
        updateLockEpoch(remote.lock_epoch ?? 0);
      } catch {
        // Offline — sync check converges later.
      }
      setPassword("");
      router.replace("/home" as any);
    } catch (err) {
      console.warn("Unlock failed", err);
      setError(err instanceof Error ? err.message : "Failed to unlock.");
    } finally {
      setSubmitting(false);
    }
  };

  const goToChooser = () => router.push("/vault" as any);
  const goToCreate = () => router.push("/vault/create" as any);

  // The server no longer has this vault. There is nothing to unlock into, so
  // the password form would only produce confusing errors — offer recovery.
  // Same two-panel frame as the landing page, so a dead vault still reads as
  // part of the product rather than as a raw error page.
  if (vaultUnavailable) {
    return (
      <View className="flex-1 flex-col bg-ground md:flex-row">
        {/* Left — copy panel, same frame as the landing page: headline plus a
            muted line. No wordmark — the screen states its own name. */}
        <View className="flex-1 justify-center bg-ground px-6 py-12 md:px-18 md:py-20">
          <View>
            <Text className="text-[34px] font-normal leading-[40px] tracking-[-0.02em] text-primary-text">
              Vault unavailable
            </Text>
            <View className="max-w-120 pt-4">
              <Text className="text-[17px] font-normal leading-6.5 text-muted-text">
                Your selection has been kept.
              </Text>
            </View>
          </View>
        </View>

        {/* Right — actions rail, identical to the landing page's. */}
        <View className="w-full items-center justify-center border-border border-t bg-panel p-6 md:w-150 md:border-t-0 md:p-12">
          <View className="w-full max-w-100 rounded-[20px] border border-border bg-card px-8 py-9">
            <View className="pt-2">
              <Text className="mx-auto max-w-[270px] text-center text-[14px] font-normal leading-[20px] text-muted-text">
                {vaultId ? `${displayVaultName(vaultId)} ` : ""}
                is no longer available on this server. Switch to another vault or
                create a new one to continue.
              </Text>
            </View>

            <Pressable
              className="mt-7 w-full items-center justify-center rounded-[10px] border border-border-strong bg-surface px-5 py-2.5"
              onPress={goToChooser}
            >
              <Text className="text-[16px] font-semibold leading-5 text-primary-text">
                Switch vault
              </Text>
            </Pressable>
            <Pressable
              className="mt-3 w-full items-center justify-center rounded-[10px] border border-border bg-surface px-5 py-2.5"
              onPress={goToCreate}
            >
              <Text className="text-[16px] font-semibold leading-5 text-primary-text">
                Create a new vault
              </Text>
            </Pressable>
          </View>
        </View>
      </View>
    );
  }

  return (
    <View className="flex-1 flex-col bg-ground md:flex-row">
      {/* Left — copy panel, same frame as the landing page: headline plus a
          muted line. No wordmark — the screen states its own name. */}
      <View className="flex-1 justify-center bg-ground px-6 py-12 md:px-18 md:py-20">
        <View>
          <Text className="text-[34px] font-normal leading-[40px] tracking-[-0.02em] text-primary-text">
            Voult is locked
          </Text>
          {needsReauth ? (
            <View className="max-w-120 pt-4">
              <Text className="text-[17px] font-normal leading-6.5 text-muted-text">
                {sessionMissing
                  ? "Your server session expired. Enter your master password to restore access to this vault."
                  : serverUnreachable
                    ? "The server is unreachable. Check that it is running, then enter your master password."
                    : "Enter your master password to restore access to this vault."}
              </Text>
            </View>
          ) : (
            <View className="max-w-120 pt-4">
              <Text className="text-[17px] font-normal leading-6.5 text-muted-text">
                {lockReason === "autolock"
                  ? "Locked automatically after inactivity."
                  : lockReason === "manual"
                    ? "Locked manually."
                    : lockReason === "peer"
                      ? "Locked from another Voult surface."
                      : "Enter your master password to unlock this vault."}
              </Text>
            </View>
          )}
        </View>
      </View>

      {/* Right — actions rail, identical to the landing page's. */}
      <View className="w-full items-center justify-center border-border border-t bg-panel p-6 md:w-150 md:border-t-0 md:p-12">
        <View className="w-full max-w-100 rounded-[20px] border border-border bg-card px-8 py-9">
          <View className="pt-2">
            <Text className="mx-auto max-w-[270px] text-center text-[14px] font-normal leading-[20px] text-muted-text">
              {vaultId ? displayVaultName(vaultId) : ""}
            </Text>
          </View>

          {/* The field and the button fill the card; the card's own 400px cap
              is what keeps them off the full screen width. */}
          <View className="mt-5">
            <TextField
              placeholder="Master password"
              secureTextEntry
              value={password}
              onChangeText={setPassword}
              onSubmitEditing={onUnlock}
            />
          </View>

          <Pressable
            className="mt-4 w-full items-center justify-center rounded-[10px] border border-border-strong bg-surface px-5 py-2.5"
            onPress={onUnlock}
            disabled={submitting || !password}
          >
            <Text className="text-[16px] font-semibold leading-5 text-primary-text">
              {submitting ? "Unlocking..." : "Unlock"}
            </Text>
          </Pressable>

          {canDeviceUnlock ? (
            <Pressable
              className="mt-3 w-full items-center justify-center rounded-[10px] border border-border bg-surface px-5 py-2.5"
              onPress={onDeviceUnlock}
              disabled={submitting}
            >
              <Text className="text-[16px] font-semibold leading-5 text-primary-text">
                Unlock with this device
              </Text>
            </Pressable>
          ) : null}

          {error ? (
            <Text className="mt-4 text-center text-sm text-red-400">{error}</Text>
          ) : null}

          {/* Quiet secondary actions, in the card next to the primary one. */}
          <Pressable
            className="mt-6 w-full items-center justify-center py-2"
            onPress={goToChooser}
          >
            <Text className="text-[14px] font-normal text-muted-text">
              Use a different vault
            </Text>
          </Pressable>

          {/* Case 3. The vault id travels with the link, which the bootstrap uses to
              route here; the recovery file itself supplies the vault it belongs to,
              so nothing has to be typed. */}
          <Pressable
            className="w-full items-center justify-center py-2"
            onPress={() => router.push(`/recover?recover=${vaultId ?? ""}` as any)}
          >
            <Text className="text-[14px] font-normal text-muted-text">
              Forgot your master password?
            </Text>
          </Pressable>
        </View>
      </View>
    </View>
  );
}
