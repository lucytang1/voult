import { useEffect, useState } from "react";
import { X } from "lucide-react";

/**
 * Settings dialog opened from the hamburger menu. Mirrors the web app's
 * Settings → Security/Extension controls that have meaning in a popup: server
 * target and inactivity timeout. All validation stays in the worker
 * (`SET_SETTINGS` normalizes the URL and clamps the timeout).
 */
export function SettingsDialog({
  open,
  vaultName,
  vaultId,
  serverUrl,
  lockTimeoutMinutes,
  busy,
  error,
  onClose,
  onSave,
}: {
  open: boolean;
  vaultName: string | null;
  vaultId: string | null;
  serverUrl: string;
  lockTimeoutMinutes: number;
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onSave: (serverUrl: string, lockTimeoutMinutes: number) => void;
}) {
  const [url, setUrl] = useState(serverUrl);
  const [minutes, setMinutes] = useState(String(lockTimeoutMinutes));

  // Re-seed when opened (or when the worker returns new values) so a cancelled
  // edit never leaks into the next open.
  useEffect(() => {
    if (!open) return;
    setUrl(serverUrl);
    setMinutes(String(lockTimeoutMinutes));
  }, [open, serverUrl, lockTimeoutMinutes]);

  if (!open) return null;

  return (
    <div
      className="overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Settings"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="dialog">
        <header className="dialog__head">
          <div>
            <h2 className="dialog__title">Settings</h2>
            <p className="dialog__sub">
              Connection and lock behaviour for this browser.
            </p>
          </div>
          <button
            type="button"
            className="mini-btn"
            aria-label="Close settings"
            onClick={onClose}
          >
            <X size={15} />
          </button>
        </header>

        {error && <p className="form-error">{error}</p>}

        <div className="dialog__scroll">
          <section className="settings-section">
            <h3 className="settings-section__title">Vault</h3>
            <div className="settings-kv">
              <span className="settings-kv__key">Name</span>
              <span className="settings-kv__value">{vaultName || "Locked"}</span>
            </div>
            <div className="settings-kv">
              <span className="settings-kv__key">Vault ID</span>
              <span className="settings-kv__value" title={vaultId ?? undefined}>
                {vaultId || "Not connected"}
              </span>
            </div>
          </section>

          <section className="settings-section">
            <h3 className="settings-section__title">Server</h3>
            <p className="settings-section__sub">
              The server this browser syncs with. Plain http only on localhost.
            </p>
            <div className="form-row">
              <label className="form-label" htmlFor="settings-server-url">
                Server URL
              </label>
              <input
                id="settings-server-url"
                className="input"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                spellCheck={false}
                placeholder="https://vault.example.com"
              />
              <p className="form-hint">
                Points this browser at another server — it does not move the vault.
              </p>
            </div>
          </section>

          <section className="settings-section">
            <h3 className="settings-section__title">Auto-lock</h3>
            <p className="settings-section__sub">
              Wipe keys and plaintext after this much inactivity. Use 0 to never auto-lock.
            </p>
            <div className="form-row">
              <label className="form-label" htmlFor="settings-autolock">
                Timeout (minutes, 0 = never, max 240)
              </label>
              <input
                id="settings-autolock"
                className="input"
                value={minutes}
                inputMode="numeric"
                onChange={(e) => setMinutes(e.target.value)}
              />
            </div>
          </section>
        </div>

        <div className="form-actions">
          <button type="button" className="btn btn--ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn--primary"
            disabled={busy || !url.trim()}
            onClick={() =>
              onSave(
                url.trim() || serverUrl,
                // 0 is a meaningful value ("Never"); don't let `||` coerce it
                // into the previous timeout.
                Number.isFinite(Number(minutes)) && minutes.trim() !== ""
                  ? Number(minutes)
                  : lockTimeoutMinutes,
              )
            }
          >
            {busy ? "Saving…" : "Save settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
