import { useEffect, useState } from "react";
import {
  Check,
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  Folder as FolderIcon,
  KeyRound,
  MousePointerClick,
  Zap,
} from "lucide-react";
import {
  folderNameFor,
  ssoItemIdentity,
  type Folder,
  type VaultItem,
} from "@voult/vault-core";
import { ssoProviderLabel } from "../../lib/messaging";
import type { LoginMatch } from "../../lib/messaging";
import { hostOf, openExternal } from "../lib";
import { ItemIcon } from "./ItemIcon";

/**
 * Right pane: item details from the mockup. Read-only by design — the popup is
 * for retrieving a login, while create/edit/delete stay in the web app.
 * Passwords never render until the user reveals them, and every reveal/copy is
 * an explicit gesture.
 */
export function ItemDetails({
  item,
  folders,
  matches,
  copied,
  onCopy,
  onFill,
  busy,
  version,
}: {
  item: VaultItem | null;
  folders: Folder[];
  matches: LoginMatch[] | null;
  copied: string | null;
  onCopy: (key: string, text: string) => void;
  onFill: (id: string) => void;
  busy: boolean;
  version: number | null;
}) {
  const [revealed, setRevealed] = useState(false);

  // Never leave an old password uncovered when the selection changes.
  useEffect(() => setRevealed(false), [item?.id]);

  if (!item) {
    return (
      <section className="details-pane">
        <div className="details-empty">
          <span className="details-empty__icon">
            <MousePointerClick size={22} />
          </span>
          <span className="details-empty__title">Select a login</span>
          <span className="details-empty__sub">
            Choose a login on the left to see its account, password, and sign-in
            methods.
          </span>
        </div>
      </section>
    );
  }

  const identity = ssoItemIdentity(item, ssoProviderLabel);
  const account = item.username ?? "";
  const title = item.site || hostOf(item.origin) || "Login";
  const folder = folderNameFor(folders, item);
  const website = item.origin || item.site;
  const isMatch = (matches ?? []).some((m) => m.id === item.id);
  const sso = item.sso ?? [];
  const hasSso = sso.length > 0;

  return (
    <section className="details-pane">
      <header className="details-head">
        <ItemIcon item={item} />
        <div className="details-head__body">
          <h2 className="details-head__title" title={title}>
            {title}
          </h2>
          <div className="details-head__sub">
            {identity && (
              <>
                <span title={identity}>{identity}</span>
                <span aria-hidden="true">·</span>
              </>
            )}
            <span>{folder}</span>
          </div>
        </div>
        {website && (
          <button
            type="button"
            className="mini-btn details-head__open"
            title={`Open ${website}`}
            aria-label="Open website in a new tab"
            onClick={() => openExternal(website)}
          >
            <ExternalLink size={15} />
          </button>
        )}
      </header>

      <div className="details-body">
        {account && (
          <div className="field">
            <div className="field__label">
              <KeyRound size={11} aria-hidden="true" />
              {item.password ? "Site account" : "Account"}
            </div>
            <div className="field__box">
              <span className="field__value" title={account}>
                {account}
              </span>
              <span className="field__actions">
                <button
                  type="button"
                  className={`mini-btn${copied === "username" ? " mini-btn--done" : ""}`}
                  title="Copy account"
                  aria-label="Copy account"
                  onClick={() => onCopy("username", account)}
                >
                  {copied === "username" ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </span>
            </div>
          </div>
        )}

        {item.password ? (
          <div className="field">
            <div className="field__label">
              <KeyRound size={11} aria-hidden="true" />
              Password
            </div>
            <div className="field__box">
              <span className={`field__value field__value--mono${revealed ? "" : " field__value--muted"}`}>
                {revealed ? item.password : "••••••••••••••"}
              </span>
              <span className="field__actions">
                <button
                  type="button"
                  className="mini-btn"
                  title={revealed ? "Hide password" : "Reveal password"}
                  aria-label={revealed ? "Hide password" : "Reveal password"}
                  onClick={() => setRevealed((v) => !v)}
                >
                  {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <button
                  type="button"
                  className={`mini-btn${copied === "password" ? " mini-btn--done" : ""}`}
                  title="Copy password"
                  aria-label="Copy password"
                  onClick={() => onCopy("password", item.password ?? "")}
                >
                  {copied === "password" ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </span>
            </div>
          </div>
        ) : (
          <div className="field">
            <div className="field__label">
              <KeyRound size={11} aria-hidden="true" />
              Password
            </div>
            <div className="field__box">
              <span className="field__value field__value--muted">
                No password stored — this login uses SSO.
              </span>
            </div>
          </div>
        )}

        {hasSso && (
          <div className="field">
            <div className="field__label">
              <KeyRound size={11} aria-hidden="true" />
              Sign-in methods
            </div>
            <div className="sso-list">
              {sso.map((method) => (
                <span key={`${method.provider}:${method.account}`} className="sso-row">
                  {method.account
                    ? `${ssoProviderLabel(method.provider)} · ${method.account}`
                    : `Sign in with ${ssoProviderLabel(method.provider)}`}
                </span>
              ))}
              {!item.password && (
                <span className="sso-note">
                  Voult highlights the site's own sign-in button. It never clicks it
                  for you.
                </span>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="details-footer">
        <div className="action-card">
          <p className="action-card__title">
            {isMatch ? "Sign in on this page" : "Login details"}
          </p>
          <p className="action-card__sub">
            {isMatch
              ? item.password
                ? "Fill your saved username and password in the active tab."
                : "Focus the site's own Continue-with button in the active tab."
              : "Open a tab on this site to fill automatically — Voult only acts on matching origins."}
          </p>
          <div className="action-card__row">
            {item.password ? (
              <button
                type="button"
                className="btn btn--primary"
                disabled={busy || !isMatch}
                onClick={() => onFill(item.id)}
              >
                <Zap size={14} />
                {isMatch ? "Fill login" : "Not this site"}
              </button>
            ) : (
              <button
                type="button"
                className="btn btn--primary"
                disabled={busy || !isMatch}
                onClick={() => onFill(item.id)}
              >
                <Zap size={14} />
                {isMatch ? "Show sign-in button" : "Not this site"}
              </button>
            )}
            {item.password ? (
              <button
                type="button"
                className="btn"
                onClick={() => onCopy("password", item.password ?? "")}
              >
                {copied === "password" ? <Check size={14} /> : <Copy size={14} />}
                Copy password
              </button>
            ) : account ? (
              <button
                type="button"
                className="btn"
                onClick={() => onCopy("username", account)}
              >
                {copied === "username" ? <Check size={14} /> : <Copy size={14} />}
                Copy account
              </button>
            ) : null}
          </div>
          <div className="action-card__meta">
            <FolderIcon size={11} aria-hidden="true" />
            {folder}
            {version !== null && <> · vault v{version}</>}
          </div>
        </div>
      </div>
    </section>
  );
}
