import { useCallback, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { sendMessage, ssoProviderLabel } from "../lib/messaging";
import type { ExtensionMessage, PopupState, VaultItem } from "../lib/messaging";
import { faviconForItem, ssoItemIdentity } from "@voult/vault-core";

type RpcResponse<T> = T | { error: string };

function isErr(r: unknown): r is { error: string } {
  return !!r && typeof r === "object" && "error" in (r as Record<string, unknown>);
}

async function call<T>(msg: ExtensionMessage): Promise<T> {
  const res = await sendMessage<RpcResponse<T>>(msg);
  if (isErr(res)) throw new Error(res.error);
  return res;
}

async function activeTabOrigin(): Promise<string | undefined> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url;
  } catch {
    return undefined;
  }
}

// Site icon: stored favicon (else `<origin>/favicon.ico`), falling back to a
// letter tile when the icon is absent or fails to load. URLs are http(s)-only
// by construction (see sanitizeFaviconUrl) — never rendered blindly.
function ItemIcon({ item }: { item: VaultItem }) {
  const [failed, setFailed] = useState(false);
  const src = faviconForItem(item);
  const letter = (item.site || item.origin || "?").charAt(0).toUpperCase();
  if (!src || failed) {
    return <span style={s.iconFallback}>{letter}</span>;
  }
  return (
    <span style={s.iconTile}>
      <img
        src={src}
        alt=""
        width={20}
        height={20}
        style={s.iconImg}
        onError={() => setFailed(true)}
        // Icons are decorative; never leak the vault via referrer.
        referrerPolicy="no-referrer"
      />
    </span>
  );
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// Popup root: onboarding → locked → unlocked (search, copy, fill, settings).
// The worker owns every secret; this view only renders projections and
// forwards gestures. Passwords are never rendered — only copied or filled.
export function Popup() {
  const [error, setError] = useState<string | null>(null);
  const [tabOrigin, setTabOrigin] = useState<string | undefined>();
  const [tabReady, setTabReady] = useState(false);
  const queryClient = useQueryClient();
  const queryKey = ["popup-state", tabOrigin ?? ""] as const;
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
    void activeTabOrigin().then((url) => {
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

  if (!state) {
    return (
      <Shell>
        <p style={s.hint}>{error ?? "Contacting service worker…"}</p>
      </Shell>
    );
  }

  return (
    <Shell>
      <Header
        status={state.status}
        insecure={state.insecureOrigin}
        onLock={() => void run(() => call<PopupState>({ type: "LOCK" }))}
        onLogout={() => void run(() => call<PopupState>({ type: "LOGOUT" }))}
      />
      {error && <p style={s.error}>{error}</p>}
      {state.status === "needs-onboarding" && (
        <Connect
          busy={busy}
          serverUrl={state.serverUrl}
          onAdopt={() => void run(() => call<PopupState>({ type: "ADOPT_SESSION" }))}
          onAutoAdopt={adoptSilent}
          onPair={(code, serverUrl) =>
            void run(() => call<PopupState>({ type: "PAIR_WITH_CODE", code, serverUrl }), true)
          }
          onSettings={(serverUrl) =>
            void run(() => call<PopupState>({ type: "SET_SETTINGS", serverUrl }))
          }
        />
      )}
      {state.status === "locked" && (
        <Locked
          busy={busy}
          vaultId={state.vaultId}
          onUnlock={(password) =>
            void run(() => call<PopupState>({ type: "UNLOCK_WITH_PASSWORD", password }), true)
          }
          onDeviceUnlock={() => void run(() => call<PopupState>({ type: "UNLOCK_WITH_DEVICE" }))}
          onSwitchVault={() => void run(() => call<PopupState>({ type: "RESET_ONBOARDING" }))}
        />
      )}
      {state.status === "unlocked" && (
        <Unlocked
          busy={busy}
          state={state}
          onFill={(id) => void run(() => call<{ ok: boolean }>({ type: "FILL_ACTIVE_TAB", id }))}
          onSettings={(serverUrl, lockTimeoutMinutes) =>
            void run(() =>
              call<PopupState>({ type: "SET_SETTINGS", serverUrl, lockTimeoutMinutes }),
            )
          }
        />
      )}
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div style={s.page}>
      <div style={s.body}>{children}</div>
    </div>
  );
}

function Header({
  status,
  insecure,
  onLock,
  onLogout,
}: {
  status: PopupState["status"];
  insecure: boolean;
  onLock: () => void;
  onLogout: () => void;
}) {
  return (
    <div style={s.header}>
      <span style={s.logo}>Voult</span>
      <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
        {insecure && <span style={s.warnBadge} title="This page is plain http">insecure page</span>}
        {status === "unlocked" && (
          <>
            <button style={s.smallBtn} onClick={onLock}>Lock</button>
            <button style={s.smallBtn} onClick={onLogout}>Log out</button>
          </>
        )}
      </span>
    </div>
  );
}

// Connect screen: password-only onboarding — the vault id is never typed.
// Primary path is session auto-discovery (web app already signed in here);
// otherwise the user enters the one-time pairing code shown in the web app
// (Settings → Connect browser extension). The worker owns every secret;
// this view only forwards gestures.
function Connect({
  busy,
  serverUrl,
  onAdopt,
  onAutoAdopt,
  onPair,
  onSettings,
}: {
  busy: boolean;
  serverUrl: string;
  onAdopt: () => void;
  onAutoAdopt: () => void;
  onPair: (code: string, serverUrl: string) => void;
  onSettings: (serverUrl: string) => void;
}) {
  const [code, setCode] = useState("");
  const [url, setUrl] = useState(serverUrl);
  // Try once on open: signed-in web app → straight to the password screen.
  // Silent: staying on Connect without a banner is the expected no-session path.
  useEffect(() => {
    onAutoAdopt();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div style={s.col}>
      <p style={s.hint}>Connect this browser to your vault — no vault ID needed.</p>
      <button style={s.primary} disabled={busy} onClick={onAdopt}>
        {busy ? "Checking…" : "I've signed in — check again"}
      </button>
      <p style={s.hint}>Or enter the one-time code from the web app:</p>
      <label style={s.label}>Pairing code</label>
      <input
        style={{ ...s.input, textTransform: "uppercase" }}
        value={code}
        onChange={(e) => setCode(e.target.value.toUpperCase())}
        placeholder="ABC123"
        spellCheck={false}
        autoComplete="one-time-code"
        maxLength={8}
      />
      <label style={s.label}>Server URL</label>
      <input
        style={s.input}
        value={url}
        onChange={(e) => {
          const v = e.target.value;
          setUrl(v);
        }}
        onBlur={() => {
          if (url.trim() && url.trim() !== serverUrl) onSettings(url.trim());
        }}
        spellCheck={false}
      />
      <button
        style={s.primary}
        disabled={busy || !code.trim()}
        onClick={() => onPair(code.trim(), url.trim() || serverUrl)}
      >
        {busy ? "Connecting…" : "Connect with code"}
      </button>
      <p style={s.hint}>Get a code: web app → Settings → Connect browser extension.</p>
    </div>
  );
}

function Locked({
  busy,
  vaultId,
  onUnlock,
  onDeviceUnlock,
  onSwitchVault,
}: {
  busy: boolean;
  vaultId: string | null;
  onUnlock: (password: string) => void;
  onDeviceUnlock: () => void;
  onSwitchVault: () => void;
}) {
  const [password, setPassword] = useState("");
  const short = vaultId ? `${vaultId.slice(0, 8)}…` : "";
  return (
    <div style={s.col}>
      <p style={s.hint}>Vault {short} is locked. Enter your master password to log in.</p>
      <form
        style={s.col}
        onSubmit={(e) => {
          e.preventDefault();
          const pw = password;
          setPassword("");
          onUnlock(pw);
        }}
      >
        <label style={s.label}>Master password</label>
        <input style={s.input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus autoComplete="current-password" />
        <button style={s.primary} disabled={busy || !password} type="submit">
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>
      <button style={s.ghost} disabled={busy} onClick={onDeviceUnlock}>
        Try device unlock instead
      </button>
      <button style={s.ghost} disabled={busy} onClick={onSwitchVault} title="Forget this vault and connect a different one">
        Wrong vault? Connect a different one
      </button>
    </div>
  );
}

function Unlocked({
  busy,
  state,
  onFill,
  onSettings,
}: {
  busy: boolean;
  state: PopupState;
  onFill: (id: string) => void;
  onSettings: (serverUrl: string, lockTimeoutMinutes: number) => void;
}) {
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const items = state.items ?? [];
  const matchIds = new Set((state.matches ?? []).map((m) => m.id));
  const q = query.trim().toLowerCase();
  const filtered = items.filter(
    (i) =>
      !q ||
      (i.username ?? "").toLowerCase().includes(q) ||
      i.site.toLowerCase().includes(q) ||
      (i.origin ?? "").toLowerCase().includes(q) ||
      (i.sso ?? [])
        .map((s) => `${ssoProviderLabel(s.provider)} ${s.account}`.trim())
        .join(" ")
        .toLowerCase()
        .includes(q),
  );
  // Matches for this tab first, then the rest alphabetically.
  const ordered = [...filtered].sort((a, b) => {
    const am = matchIds.has(a.id) ? 0 : 1;
    const bm = matchIds.has(b.id) ? 0 : 1;
    return am - bm || a.site.localeCompare(b.site);
  });

  const doCopy = async (key: string, text: string) => {
    const ok = await copyText(text);
    setCopied(ok ? key : null);
    window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 1200);
  };

  // Saved SSO for this site: one tap closes the popup and focuses the site's
  // own Continue-with button in the tab (the message chain outlives the
  // popup, so closing immediately is safe). Only passwordless logins suggest
  // here — logins with a password fill normally. One row per sign-in method,
  // naming the account, so two Google accounts stay distinguishable.
  const oauthMatches = (state.matches ?? []).filter(
    (m) => !m.hasPassword && m.sso.length > 0,
  );
  const suggestSignIn = (id: string) => {
    onFill(id);
    window.close();
  };

  return (
    <div style={s.col}>
      {state.insecureOrigin && (
        <p style={s.warn}>This page is plain http — fill only on sites you trust.</p>
      )}
      {oauthMatches.length > 0 && (
        <div style={s.suggestBox}>
          {oauthMatches.flatMap((m) =>
            m.sso.map((method) => (
              <button
                key={`${m.id}:${method.provider}:${method.account}`}
                style={s.suggestBtn}
                title={`Focus the site's Continue with ${ssoProviderLabel(method.provider)} button`}
                onClick={() => suggestSignIn(m.id)}
              >
                Sign in with {ssoProviderLabel(method.provider)}
                {method.account ? ` · ${method.account}` : ""}
              </button>
            )),
          )}
        </div>
      )}
      {state.matches && state.matches.length > 0 && (
        <p style={s.hint}>
          {state.matches.length} login{state.matches.length === 1 ? "" : "s"} for this site.
        </p>
      )}
      <input style={s.input} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search logins…" />
      <div style={s.list}>
        {ordered.length === 0 && <p style={s.hint}>No logins yet — save one from a login page.</p>}
        {ordered.slice(0, 50).map((item: VaultItem) => {
          // A provider-only sign-in (no account) leads with the method name so
          // the row is never blank; its provider suffix is then redundant.
          const identity = ssoItemIdentity(item, ssoProviderLabel);
          const named = !identity.startsWith("Sign in with");
          return (
          <div key={item.id} style={s.row}>
            <ItemIcon item={item} />
            <div style={s.rowMain}>
              <span style={s.rowUser}>
                {identity}
              </span>
              <span style={s.rowSite}>
                {item.site || item.origin}
                {(item.sso ?? []).length > 0 && named
                  ? ` · ${[...new Set((item.sso ?? []).map((x) => x.provider))].map(ssoProviderLabel).join(", ")}`
                  : ""}
              </span>
            </div>
            <span style={{ display: "flex", gap: 4 }}>
              <button style={s.smallBtn} title="Copy username" onClick={() => void doCopy(`${item.id}:u`, item.username ?? "")}>
                {copied === `${item.id}:u` ? "✓" : "User"}
              </button>
              {item.password ? (
                <>
                  <button style={s.smallBtn} title="Copy password" onClick={() => void doCopy(`${item.id}:p`, item.password ?? "")}>
                    {copied === `${item.id}:p` ? "✓" : "Pass"}
                  </button>
                  <button style={s.smallBtn} disabled={busy} title="Fill in active tab" onClick={() => onFill(item.id)}>
                    Fill
                  </button>
                </>
              ) : (
                <span style={s.oauthBadge} title="SSO login — no password to fill">SSO</span>
              )}
              {item.password && (item.sso ?? []).length > 0 && (
                <span style={s.oauthBadge} title={`Also signs in with ${(item.sso ?? []).map((x) => ssoProviderLabel(x.provider)).join(", ")}`}>+SSO</span>
              )}
            </span>
          </div>
          );
        })}
      </div>
      <button style={s.ghost} onClick={() => setShowSettings((v) => !v)}>
        {showSettings ? "Hide settings" : "Settings"}
      </button>
      {showSettings && (
        <SettingsForm
          serverUrl={state.serverUrl}
          lockTimeoutMinutes={state.lockTimeoutMinutes}
          onSave={onSettings}
        />
      )}
    </div>
  );
}

function SettingsForm({
  serverUrl,
  lockTimeoutMinutes,
  onSave,
}: {
  serverUrl: string;
  lockTimeoutMinutes: number;
  onSave: (serverUrl: string, lockTimeoutMinutes: number) => void;
}) {
  const [url, setUrl] = useState(serverUrl);
  const [mins, setMins] = useState(String(lockTimeoutMinutes));
  return (
    <div style={s.col}>
      <label style={s.label}>Server URL (https required except localhost)</label>
      <input style={s.input} value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
      <label style={s.label}>Auto-lock after inactivity (minutes, 1–120)</label>
      <input style={s.input} value={mins} inputMode="numeric" onChange={(e) => setMins(e.target.value)} />
      <button style={s.primary} onClick={() => onSave(url.trim() || serverUrl, Number(mins) || lockTimeoutMinutes)}>
        Save settings
      </button>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  page: { fontFamily: "system-ui, -apple-system, sans-serif", background: "#0f1115", color: "#e8eaf0", width: 400, minHeight: 560 },
  body: { display: "flex", flexDirection: "column", gap: 10, padding: "0 16px 16px" },
  header: { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 0 10px", borderBottom: "1px solid #23262e" },
  logo: { fontWeight: 700, fontSize: 16 },
  col: { display: "flex", flexDirection: "column", gap: 8 },
  label: { fontSize: 12, color: "#9aa0ae" },
  input: { background: "#17191f", border: "1px solid #333845", borderRadius: 8, color: "#e8eaf0", padding: "8px 10px", fontSize: 13, outline: "none" },
  primary: { background: "#4f7cff", border: 0, borderRadius: 8, color: "#fff", padding: "9px 10px", fontSize: 13, fontWeight: 600, cursor: "pointer" },
  ghost: { background: "none", border: 0, color: "#9aa0ae", fontSize: 12, cursor: "pointer", padding: 4 },
  smallBtn: { background: "#23262e", border: 0, borderRadius: 6, color: "#e8eaf0", padding: "5px 9px", fontSize: 12, cursor: "pointer" },
  hint: { color: "#9aa0ae", fontSize: 13, margin: 0 },
  error: { color: "#ff9d9d", fontSize: 13, margin: 0 },
  warn: { color: "#e0b34e", fontSize: 12, margin: 0 },
  warnBadge: { fontSize: 11, background: "#4a3a12", color: "#e0b34e", borderRadius: 999, padding: "3px 10px" },
  list: { display: "flex", flexDirection: "column", gap: 6, maxHeight: 320, overflowY: "auto" },
  row: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, background: "#17191f", border: "1px solid #262a35", borderRadius: 8, padding: "7px 9px" },
  rowMain: { display: "flex", flexDirection: "column", minWidth: 0, flex: 1 },
  rowUser: { fontWeight: 600, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  rowSite: { color: "#9aa0ae", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  oauthBadge: { fontSize: 11, background: "#2c3a2c", color: "#9fd6a4", borderRadius: 999, padding: "4px 10px", alignSelf: "center" },
  iconTile: { width: 32, height: 32, borderRadius: 12, flexShrink: 0, background: "transparent", display: "inline-flex", alignItems: "center", justifyContent: "center" },
  iconImg: { width: 22, height: 22, borderRadius: 4, objectFit: "contain" as const },
  iconFallback: { width: 32, height: 32, borderRadius: 12, flexShrink: 0, background: "#fff", color: "#252833", fontSize: 14, fontWeight: 700, display: "inline-flex", alignItems: "center", justifyContent: "center" },
  suggestBox: { display: "flex", flexDirection: "column", gap: 6 },
  suggestBtn: { background: "#4f7cff", border: 0, borderRadius: 8, color: "#fff", padding: "10px", fontSize: 13, fontWeight: 600, cursor: "pointer", textAlign: "center" },
};
