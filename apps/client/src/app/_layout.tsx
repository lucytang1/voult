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
      // SQLite is opened per-account (file:voult-<userId>.db) and only once a
      // session exists — never globally at startup, so pre-auth code cannot
      // touch any account's intent log or client state.
      // Existing-session unlock: if the session cookie is valid and the
      // browser device key + envelope exist, restore the unlocked vault
      // without requesting the master password. Skipped when the user
      // explicitly locked the vault (sessionStorage flag) so a reload can't
      // silently re-unlock — they must go through /lock instead.
      try {
        const lockedFlag = isLockedFlagSet();
        const unlocked = lockedFlag ? null : await unlockWithDevice();
        if (unlocked) {
          await initSQLite(unlocked.session.user.id);
          setVaultKey(unlocked.vaultKey);
          setSession(unlocked.session);
          updateDecryptedVault(unlocked.decryptedVault);
          updateVaultVersion(unlocked.version);
        } else if (lockedFlag) {
          // Locked after a reload: in-memory session is gone but the cookie
          // may still be valid. Restore just the session so the app enters
          // the Authenticated+Locked state and /lock accepts it.
          const sessionData = await fetchSession();
          await initSQLite(sessionData.user.id);
          setSession({ user: sessionData.user, cryptoVersion: CRYPTO_VERSION });
        }
        router.navigate((lockedFlag ? "/lock" : "/home") as any);

      } catch (e) {
        // No valid session, missing device key/envelope, or network error —
        // stay on the landing/login screen.
        console.log("No session to restore", e);
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
