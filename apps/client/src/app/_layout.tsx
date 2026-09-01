import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Slot } from "expo-router";
import "../../global.css";
import { initSQLite } from "../lib/sqlite/web/init-db";
import { useSyncTriggers } from "../lib/sync/use-sync-triggers";
import { useEffect, useState } from "react";
import {
  setSession,
  setVaultKey,
  updateDecryptedVault,
  updateVaultVersion,
  isLockedFlagSet,
} from "../lib/state";
import { unlockWithDevice } from "../lib/auth/flows";
import { fetchSession } from "../lib/queries/session/query";
import { CRYPTO_VERSION } from "../lib/crypto/index.web";
const queryClient = new QueryClient();
import { router } from 'expo-router';

export default function RootLayout() {
  // useSyncTriggers();
  useEffect(() => {
    const bootstrap = async () => {
      // Case 2: session present -> restore app using session and if locked unlock via master password.
      // Case 1: no session -> stay on landing ("/") which offers two options (create locally or cloud sync).
      // SQLite is opened per-vault only once a session exists.

      // Skip auto-restore when handling Google OAuth callback with pending state —
      // the vault chooser at /vault handles that UX.
      if (typeof window !== "undefined" && window.location.search.includes("google_pending_state")) {
        return;
      }

      try {
        const lockedFlag = isLockedFlagSet();

        // Probe whether a session cookie exists at all.
        let sessionData: Awaited<ReturnType<typeof fetchSession>> | null = null;
        try {
          sessionData = await fetchSession();
        } catch {
          // No valid session -> stay on landing for Case 1.
          console.log("No session to restore — showing landing");
          return;
        }

        if (lockedFlag) {
          // Locked after a reload: restore just the session so /lock can accept it.
          await initSQLite(sessionData.vault_id);
          setSession({ vaultId: sessionData.vault_id, cryptoVersion: sessionData.crypto_version });
          router.navigate("/lock" as any);
          return;
        }

        // Not locked -> try silent device unlock (no password).
        try {
          const unlocked = await unlockWithDevice();
          if (unlocked) {
            await initSQLite(unlocked.session.vaultId);
            setVaultKey(unlocked.vaultKey);
            setSession(unlocked.session);
            updateDecryptedVault(unlocked.decryptedVault);
            updateVaultVersion(unlocked.version);
            router.navigate("/home" as any);
            return;
          }
        } catch (e) {
          console.log("Device unlock failed, falling back to password unlock", e);
        }

        // Session exists but device unlock unavailable -> need master password.
        await initSQLite(sessionData.vault_id);
        setSession({ vaultId: sessionData.vault_id, cryptoVersion: sessionData.crypto_version });
        router.navigate("/lock" as any);
      } catch (e) {
        console.log("Bootstrap error", e);
      }
    };
    bootstrap();
  }, []);
  return (
    // <PostHogProvider apiKey="phc_hPhzKttZrCe9Mv8wYiXdCYq7nQsl6LypkOK2853BnnK" options={{
    //   host: 'https://prp.lucytang.dev',
    //   customStorage: AsyncStorage
    // }}>
    // {/* </PostHogProvider> */}
    <QueryClientProvider client={queryClient}>
      <Slot />
    </QueryClientProvider>
  );
}
