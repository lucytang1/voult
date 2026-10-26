import { ExternalLink, Lock, LogOut, Settings, Shield } from "lucide-react";
import { shortVaultId } from "../lib";

/**
 * Hamburger menu: the mockup's "Menu (Settings & Open app)" plus the two
 * lifecycle actions that must stay reachable without hunting: Lock and Log out.
 * Rendered above the panes with a transparent backdrop that closes it.
 */
export function MenuPopover({
  status,
  vaultName,
  vaultId,
  serverUrl,
  onClose,
  onSettings,
  onOpenApp,
  onLock,
  onLogout,
}: {
  status: "needs-onboarding" | "locked" | "unlocked";
  vaultName: string | null;
  vaultId: string | null;
  serverUrl: string;
  onClose: () => void;
  onSettings: () => void;
  onOpenApp: () => void;
  onLock: () => void;
  onLogout: () => void;
}) {
  return (
    <>
      <button
        type="button"
        className="menu-backdrop"
        aria-label="Close menu"
        tabIndex={-1}
        onClick={onClose}
      />
      <div className="menu" role="menu" aria-label="Vault menu">
        <div className="menu__head">
          <div className="menu__brand">
            <Shield size={17} color="var(--accent-text)" aria-hidden="true" />
            Voult
          </div>
          <div className="menu__vault">
            {vaultName || (vaultId ? `Vault ${shortVaultId(vaultId)}` : "Not connected")}
          </div>
        </div>

        <button type="button" className="menu__item" role="menuitem" onClick={onSettings}>
          <Settings size={15} aria-hidden="true" />
          Settings
        </button>
        <button
          type="button"
          className="menu__item"
          role="menuitem"
          onClick={onOpenApp}
          disabled={!serverUrl}
        >
          <ExternalLink size={15} aria-hidden="true" />
          Open app
        </button>

        {status === "unlocked" && (
          <>
            <div className="menu__sep" role="separator" />
            <button type="button" className="menu__item" role="menuitem" onClick={onLock}>
              <Lock size={15} aria-hidden="true" />
              Lock vault
            </button>
            <button
              type="button"
              className="menu__item menu__item--danger"
              role="menuitem"
              onClick={onLogout}
            >
              <LogOut size={15} aria-hidden="true" />
              Log out
            </button>
          </>
        )}
      </div>
    </>
  );
}
