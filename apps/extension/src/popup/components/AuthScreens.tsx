import { useEffect, useState } from "react";
import { ArrowRight, KeyRound, Lock, Shield } from "lucide-react";
import { shortVaultId } from "../lib";

function Brand() {
  return (
    <div className="auth__brand">
      <Shield size={19} color="var(--accent-text)" aria-hidden="true" />
      <span className="auth__brand-name">Voult</span>
    </div>
  );
}

export function LoadingScreen({ message }: { message: string }) {
  return (
    <div className="auth__busy">
      <Brand />
      <span style={{ marginLeft: 6 }}>{message}</span>
    </div>
  );
}

/**
 * Connect screen (fresh install): password-only onboarding — the vault id is
 * never typed. Primary path is session auto-discovery (web app already signed
 * in in this profile); otherwise redeem the one-time pairing code shown in the
 * web app. The worker owns every secret; this view only forwards gestures.
 */
export function ConnectScreen({
  busy,
  serverUrl,
  onAdopt,
  onAutoAdopt,
  onPair,
  onServerUrl,
}: {
  busy: boolean;
  serverUrl: string;
  onAdopt: () => void;
  onAutoAdopt: () => void;
  onPair: (code: string, serverUrl: string) => void;
  onServerUrl: (serverUrl: string) => void;
}) {
  const [code, setCode] = useState("");
  const [url, setUrl] = useState(serverUrl);

  // Try once on open: a signed-in web app in this profile jumps straight to
  // the password screen. Staying here without a banner is the expected path.
  useEffect(() => {
    onAutoAdopt();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="auth">
      <div className="auth__card">
        <Brand />
        <span className="auth__icon">
          <KeyRound size={20} />
        </span>
        <h1 className="auth__title">Connect this browser</h1>
        <p className="auth__sub">
          Link the extension to your vault — no vault ID to type. Sign in on the
          web app first, or use a one-time code from its settings.
        </p>

        <button type="button" className="btn btn--primary btn--block" disabled={busy} onClick={onAdopt}>
          {busy ? "Checking…" : "I've signed in — check again"}
        </button>

        <div className="auth__divider">or use a pairing code</div>

        <div className="form-row">
          <label className="form-label" htmlFor="pairing-code">
            Pairing code
          </label>
          <input
            id="pairing-code"
            className="input"
            value={code}
            onChange={(e) => setCode(e.target.value.toUpperCase())}
            placeholder="ABC123"
            spellCheck={false}
            autoComplete="one-time-code"
            maxLength={8}
            style={{ textTransform: "uppercase", letterSpacing: "0.12em" }}
          />
        </div>

        <div className="form-row">
          <label className="form-label" htmlFor="server-url">
            Server URL
          </label>
          <input
            id="server-url"
            className="input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onBlur={() => {
              if (url.trim() && url.trim() !== serverUrl) onServerUrl(url.trim());
            }}
            spellCheck={false}
            placeholder="http://localhost:8080"
          />
        </div>

        <button
          type="button"
          className="btn btn--primary btn--block"
          disabled={busy || !code.trim()}
          onClick={() => onPair(code.trim(), url.trim() || serverUrl)}
        >
          {busy ? "Connecting…" : "Connect with code"}
          {!busy && <ArrowRight size={14} />}
        </button>

        <p className="auth__hint">
          Get a code in the web app under Settings → Extension → Connect browser
          extension.
        </p>
      </div>
    </div>
  );
}

/** Locked screen: local password unlock, silent device unlock, or re-pair. */
export function LockedScreen({
  busy,
  vaultName,
  vaultId,
  onUnlock,
  onDeviceUnlock,
  onSwitchVault,
}: {
  busy: boolean;
  vaultName: string | null;
  vaultId: string | null;
  onUnlock: (password: string) => void;
  onDeviceUnlock: () => void;
  onSwitchVault: () => void;
}) {
  const [password, setPassword] = useState("");
  const label = vaultName || `Vault ${shortVaultId(vaultId)}`;

  return (
    <div className="auth">
      <div className="auth__card">
        <Brand />
        <span className="auth__icon">
          <Lock size={20} />
        </span>
        <h1 className="auth__title">Vault is locked</h1>
        <p className="auth__sub">
          {label} · enter your master password. It is checked on this device —
          a wrong password never reaches the server.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            const pw = password;
            setPassword("");
            onUnlock(pw);
          }}
        >
          <div className="form-row">
            <label className="form-label" htmlFor="master-password">
              Master password
            </label>
            <input
              id="master-password"
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              autoComplete="current-password"
            />
          </div>
          <button
            type="submit"
            className="btn btn--primary btn--block"
            disabled={busy || !password}
          >
            {busy ? "Unlocking…" : "Unlock vault"}
          </button>
        </form>

        <div className="auth__actions">
          <button
            type="button"
            className="btn btn--ghost btn--block"
            disabled={busy}
            onClick={onDeviceUnlock}
          >
            Try device unlock instead
          </button>
          <button
            type="button"
            className="btn btn--ghost btn--block"
            disabled={busy}
            onClick={onSwitchVault}
            title="Forget this vault and connect a different one"
          >
            Wrong vault? Connect a different one
          </button>
        </div>
      </div>
    </div>
  );
}
