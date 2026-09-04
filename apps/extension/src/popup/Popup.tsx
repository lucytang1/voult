import { useCallback, useEffect, useState } from "react";
import { sendMessage } from "../lib/messaging";
import type { ExtensionMessage, PopupState, VaultItem } from "../lib/messaging";

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
  const [state, setState] = useState<PopupState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    setError(null);
    const tabUrl = await activeTabOrigin();
    setState(await call<PopupState>({ type: "GET_STATE", tabOrigin: tabUrl }));
  }, []);

  useEffect(() => {
    void refresh().catch((e: unknown) =>
      setError(e instanceof Error ? e.message : "Worker unreachable."),
    );
  }, [refresh]);

  const run = useCallback(
    async (fn: () => Promise<PopupState | { ok: boolean }>) => {
      setBusy(true);
      setError(null);
      try {
        const res = await fn();
        if ("status" in res) setState(res);
        else await refresh();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Request failed.");
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

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
        <Onboarding
          busy={busy}
          serverUrl={state.serverUrl}
          onSave={(vaultId, serverUrl) =>
            void run(() => call<PopupState>({ type: "SAVE_ONBOARDING", vaultId, serverUrl }))
          }
        />
      )}
      {state.status === "locked" && (
        <Locked
          busy={busy}
          vaultId={state.vaultId}
          onUnlock={(password) =>
            void run(() => call<PopupState>({ type: "UNLOCK_WITH_PASSWORD", password }))
          }
          onDeviceUnlock={() => void run(() => call<PopupState>({ type: "UNLOCK_WITH_DEVICE" }))}
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

function Onboarding({
  busy,
  serverUrl,
  onSave,
}: {
  busy: boolean;
  serverUrl: string;
  onSave: (vaultId: string, serverUrl: string) => void;
}) {
  const [vaultId, setVaultId] = useState("");
  const [url, setUrl] = useState(serverUrl);
  return (
    <div style={s.col}>
      <p style={s.hint}>Connect this browser to your vault. Find the vault ID in the Voult web app.</p>
      <label style={s.label}>Vault ID (UUID)</label>
      <input style={s.input} value={vaultId} onChange={(e) => setVaultId(e.target.value)} placeholder="xxxxxxxx-xxxx-…" spellCheck={false} />
      <label style={s.label}>Server URL</label>
      <input style={s.input} value={url} onChange={(e) => setUrl(e.target.value)} spellCheck={false} />
      <button style={s.primary} disabled={busy || !vaultId.trim()} onClick={() => onSave(vaultId.trim(), url.trim() || serverUrl)}>
        {busy ? "Saving…" : "Connect vault"}
      </button>
    </div>
  );
}

function Locked({
  busy,
  vaultId,
  onUnlock,
  onDeviceUnlock,
}: {
  busy: boolean;
  vaultId: string | null;
  onUnlock: (password: string) => void;
  onDeviceUnlock: () => void;
}) {
  const [password, setPassword] = useState("");
  const short = vaultId ? `${vaultId.slice(0, 8)}…` : "";
  return (
    <div style={s.col}>
      <p style={s.hint}>Vault {short} is locked.</p>
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
      i.username.toLowerCase().includes(q) ||
      i.site.toLowerCase().includes(q) ||
      (i.origin ?? "").toLowerCase().includes(q),
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

  return (
    <div style={s.col}>
      {state.insecureOrigin && (
        <p style={s.warn}>This page is plain http — fill only on sites you trust.</p>
      )}
      {state.matches && state.matches.length > 0 && (
        <p style={s.hint}>
          {state.matches.length} login{state.matches.length === 1 ? "" : "s"} for this site.
        </p>
      )}
      <input style={s.input} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search logins…" />
      <div style={s.list}>
        {ordered.length === 0 && <p style={s.hint}>No logins yet — save one from a login page.</p>}
        {ordered.slice(0, 50).map((item: VaultItem) => (
          <div key={item.id} style={s.row}>
            <div style={s.rowMain}>
              <span style={s.rowUser}>{item.username}</span>
              <span style={s.rowSite}>{item.site || item.origin}</span>
            </div>
            <span style={{ display: "flex", gap: 4 }}>
              <button style={s.smallBtn} title="Copy username" onClick={() => void doCopy(`${item.id}:u`, item.username)}>
                {copied === `${item.id}:u` ? "✓" : "User"}
              </button>
              <button style={s.smallBtn} title="Copy password" onClick={() => void doCopy(`${item.id}:p`, item.password)}>
                {copied === `${item.id}:p` ? "✓" : "Pass"}
              </button>
              <button style={s.smallBtn} disabled={busy} title="Fill in active tab" onClick={() => onFill(item.id)}>
                Fill
              </button>
            </span>
          </div>
        ))}
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
  rowMain: { display: "flex", flexDirection: "column", minWidth: 0 },
  rowUser: { fontWeight: 600, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  rowSite: { color: "#9aa0ae", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
};
