import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Menu } from "lucide-react";
import { itemsInFolder } from "@voult/vault-core";
import { ssoProviderLabel } from "../lib/messaging";
import type { ExtensionMessage, PopupState } from "../lib/messaging";
import { activeTabUrl, call, copyText, openExternal } from "./lib";
import { TopBar } from "./components/TopBar";
import { MenuPopover } from "./components/MenuPopover";
import { ItemList } from "./components/ItemList";
import { ItemDetails } from "./components/ItemDetails";
import { SettingsDialog } from "./components/SettingsDialog";
import { ConnectScreen, LoadingScreen, LockedScreen } from "./components/AuthScreens";

/**
 * Popup root: onboarding → locked → unlocked. The worker owns every secret;
 * this view renders projections and forwards gestures. Passwords are never
 * rendered unless the user reveals them, and only copy/fill leaves the popup.
 */
export function Popup() {
  const [error, setError] = useState<string | null>(null);
  const [tabOrigin, setTabOrigin] = useState<string | undefined>();
  const [tabReady, setTabReady] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();
  const queryKey = useMemo(() => ["popup-state", tabOrigin ?? ""] as const, [tabOrigin]);

  const stateQuery = useQuery({
    queryKey,
    queryFn: () => call<PopupState>({ type: "GET_STATE", tabOrigin }),
    enabled: tabReady,
    retry: false,
    staleTime: 0,
    gcTime: 0,
  });
  const command = useMutation({
    mutationFn: (execute: () => Promise<void>) => execute(),
    // Commands may carry an unlock password or pairing code in their closure.
    gcTime: 0,
  });
  const state = stateQuery.data ?? null;
  const busy = command.isPending;

  useEffect(() => {
    let mounted = true;
    void activeTabUrl().then((url) => {
      if (!mounted) return;
      setTabOrigin(url);
      setTabReady(true);
    });
    return () => {
      mounted = false;
      // Popup state includes vault item passwords. Do not keep it after the
      // popup closes, even though the QueryClient itself is short-lived.
      queryClient.removeQueries({ queryKey: ["popup-state"] });
      queryClient.clear();
    };
  }, [queryClient]);

  useEffect(() => {
    if (!stateQuery.error) return;
    setError(stateQuery.error instanceof Error ? stateQuery.error.message : "Worker unreachable.");
  }, [stateQuery.error]);

  // Escape closes the menu first, then the settings dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (menuOpen) setMenuOpen(false);
      else if (settingsOpen) setSettingsOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menuOpen, settingsOpen]);

  const run = useCallback(
    async (fn: () => Promise<PopupState | { ok: boolean }>, sensitive = false) => {
      setError(null);
      try {
        const execute = async () => {
          const result = await fn();
          if ("status" in result) queryClient.setQueryData(queryKey, result);
          else await stateQuery.refetch();
        };
        // Passwords and one-time pairing codes stay out of mutation variables
        // and cache; their RPCs run directly and only the sanitized UI state
        // is written to the short-lived query.
        if (sensitive) await execute();
        else await command.mutateAsync(execute);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Request failed.");
      } finally {
        // Mutation variables are callbacks; reset so a completed popup action
        // cannot retain its closure for the lifetime of the open popup.
        command.reset();
      }
    },
    [command, queryClient, queryKey, stateQuery.refetch],
  );

  // Silent one-shot auto-discovery for the Connect screen: a web session in
  // this profile jumps straight to the password screen. "No session" is not
  // an error here — the user just pairs with a code instead.
  const adoptSilent = useCallback(async () => {
    try {
      await command.mutateAsync(async () => {
        const adopted = await call<PopupState>({ type: "ADOPT_SESSION" });
        queryClient.setQueryData(queryKey, adopted);
      });
    } catch {
      // No web session — stay on Connect, no error banner.
    } finally {
      command.reset();
    }
  }, [command, queryClient, queryKey]);

  const copy = useCallback(async (key: string, text: string) => {
    const ok = await copyText(text);
    setCopied(ok ? key : null);
    if (ok) {
      window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 1200);
    }
  }, []);

  // Folder filter gestures go to the worker, which owns the value: it persists
  // it for the unlocked lifetime and uses it to scope page suggestions and save
  // destinations. The reply is a full state, so the list repaints optimistically
  // here and is then replaced by the worker's normalized truth (a dangling id
  // falls back to All folders).
  const chooseFolder = useCallback(
    (value: string | null) => {
      setError(null);
      queryClient.setQueryData<PopupState>(queryKey, (prev) =>
        prev ? { ...prev, selectedFolderId: value } : prev,
      );
      void call<PopupState>({ type: "SET_FOLDER", folderId: value, tabOrigin })
        .then((next) => queryClient.setQueryData(queryKey, next))
        .catch((e) => setError(e instanceof Error ? e.message : "Could not change folder."));
    },
    [queryClient, queryKey, tabOrigin],
  );

  const items = state?.items ?? [];
  const folders = state?.folders ?? [];
  const matches = state?.matches ?? null;
  // The worker owns the folder filter (it must outlive the popup); this is a
  // projection of it, never popup-local state. Null = All folders.
  const selectedFolderId = state?.selectedFolderId ?? null;

  // Folder view: null = all items; "unfiled" = the shared Unfiled bucket.
  const scopedItems = useMemo(() => {
    if (selectedFolderId === null) return items;
    return itemsInFolder(
      items,
      folders,
      selectedFolderId === "unfiled" ? null : selectedFolderId,
    );
  }, [items, folders, selectedFolderId]);

  const filteredItems = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return scopedItems;
    return scopedItems.filter((item) => {
      const sso = (item.sso ?? [])
        .map((s) => `${ssoProviderLabel(s.provider)} ${s.account}`.trim())
        .join(" ");
      return `${item.site} ${item.username ?? ""} ${item.origin ?? ""} ${sso}`
        .toLowerCase()
        .includes(q);
    });
  }, [scopedItems, query]);

  // Drop a stale selection when the item leaves the current view.
  useEffect(() => {
    if (selectedId && !filteredItems.some((i) => i.id === selectedId)) {
      setSelectedId(null);
    }
  }, [filteredItems, selectedId]);

  const selectedItem =
    filteredItems.find((item) => item.id === selectedId) ?? filteredItems[0] ?? null;

  // Suggestions are folder-scoped twice: the worker already filters `matches`
  // to the selected folder, and intersecting with the visible items keeps the
  // block honest during the optimistic filter switch (before the reply lands).
  const scopedIds = useMemo(() => new Set(scopedItems.map((item) => item.id)), [scopedItems]);
  const oauthMatches = (matches ?? []).filter(
    (m) => scopedIds.has(m.id) && !m.hasPassword && m.sso.length > 0,
  );

  const fill = useCallback(
    (id: string) => {
      void run(() => call<{ ok: boolean }>({ type: "FILL_ACTIVE_TAB", id }));
    },
    [run],
  );

  // A suggestion closes the popup immediately: the message chain outlives the
  // popup, and the content script needs the tab focused to highlight the site's
  // own Continue-with button.
  const suggest = useCallback(
    (id: string) => {
      fill(id);
      window.setTimeout(() => window.close(), 60);
    },
    [fill],
  );

  const closeMenu = useCallback(() => setMenuOpen(false), []);

  const openSettings = useCallback(() => {
    setMenuOpen(false);
    setError(null);
    setSettingsOpen(true);
  }, []);

  const openApp = useCallback(() => {
    if (!state) return;
    setMenuOpen(false);
    openExternal(state.serverUrl);
  }, [state]);

  const lockVault = useCallback(() => {
    setMenuOpen(false);
    setSettingsOpen(false);
    void run(() => call<PopupState>({ type: "LOCK" }));
  }, [run]);

  const logout = useCallback(() => {
    setMenuOpen(false);
    setSettingsOpen(false);
    void run(() => call<PopupState>({ type: "LOGOUT" }));
  }, [run]);

  const saveSettings = useCallback(
    (serverUrl: string, lockTimeoutMinutes: number) => {
      void run(async () => {
        const next = await call<PopupState>({
          type: "SET_SETTINGS",
          serverUrl,
          lockTimeoutMinutes,
        });
        setSettingsOpen(false);
        return next;
      });
    },
    [run],
  );

  if (!state) {
    return (
      <div className="shell">
        <LoadingScreen message={error ?? "Contacting service worker…"} />
      </div>
    );
  }

  const unlocked = state.status === "unlocked";

  return (
    <div className="shell">
      {unlocked ? (
        <TopBar
          query={query}
          onQueryChange={setQuery}
          folders={folders}
          items={items}
          selectedFolderId={selectedFolderId}
          onFolderChange={chooseFolder}
          menuOpen={menuOpen}
          onToggleMenu={() => setMenuOpen((v) => !v)}
          searchRef={searchRef}
        />
      ) : (
        <div className="auth-topbar">
          <button
            type="button"
            className={`icon-btn${menuOpen ? " icon-btn--active" : ""}`}
            aria-label="Vault menu"
            aria-haspopup="menu"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((v) => !v)}
          >
            <Menu size={17} />
          </button>
          <span className="menu__brand">Voult</span>
        </div>
      )}

      {error && !settingsOpen && <p className="form-error error-strip">{error}</p>}

      {unlocked ? (
        <>
          {state.insecureOrigin && (
            <div className="warn-strip">
              This page is plain http — fill only on sites you trust.
            </div>
          )}
          {state.serverSessionMissing && (
            <div className="warn-strip">
              Server session expired. The vault stays usable here; syncing resumes after you sign in
              again in the web app.
            </div>
          )}
          <div className="panes">
            <ItemList
              items={filteredItems}
              matches={matches}
              selectedId={selectedItem?.id ?? null}
              onSelect={setSelectedId}
              oauthMatches={oauthMatches}
              onSuggest={suggest}
              busy={busy}
              hasAnyItems={items.length > 0}
            />
            <ItemDetails
              item={selectedItem}
              folders={folders}
              matches={matches}
              copied={copied}
              onCopy={(key, text) => void copy(key, text)}
              onFill={fill}
              busy={busy}
              version={state.version}
            />
          </div>
        </>
      ) : state.status === "locked" ? (
        <LockedScreen
          busy={busy}
          vaultName={state.vaultName}
          vaultId={state.vaultId}
          onUnlock={(password) =>
            void run(() => call<PopupState>({ type: "UNLOCK_WITH_PASSWORD", password }), true)
          }
          onDeviceUnlock={() => void run(() => call<PopupState>({ type: "UNLOCK_WITH_DEVICE" }))}
          onSwitchVault={() => void run(() => call<PopupState>({ type: "RESET_ONBOARDING" }))}
        />
      ) : (
        <ConnectScreen
          busy={busy}
          serverUrl={state.serverUrl}
          onAdopt={() => void run(() => call<PopupState>({ type: "ADOPT_SESSION" }))}
          onAutoAdopt={adoptSilent}
          onPair={(code, serverUrl) =>
            void run(() => call<PopupState>({ type: "PAIR_WITH_CODE", code, serverUrl }), true)
          }
          onServerUrl={(serverUrl) =>
            void run(() => call<PopupState>({ type: "SET_SETTINGS", serverUrl }))
          }
        />
      )}

      {menuOpen && (
        <MenuPopover
          status={state.status}
          vaultName={state.vaultName}
          vaultId={state.vaultId}
          serverUrl={state.serverUrl}
          onClose={closeMenu}
          onSettings={openSettings}
          onOpenApp={openApp}
          onLock={lockVault}
          onLogout={logout}
        />
      )}

      <SettingsDialog
        open={settingsOpen}
        vaultName={state.vaultName}
        vaultId={state.vaultId}
        serverUrl={state.serverUrl}
        lockTimeoutMinutes={state.lockTimeoutMinutes}
        busy={busy}
        error={settingsOpen ? error : null}
        onClose={() => {
          setSettingsOpen(false);
          setError(null);
        }}
        onSave={saveSettings}
      />
    </div>
  );
}
