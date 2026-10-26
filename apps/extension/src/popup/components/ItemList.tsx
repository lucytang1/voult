import { ssoProviderLabel } from "../../lib/messaging";
import type { LoginMatch } from "../../lib/messaging";
import { ssoItemIdentity, type VaultItem } from "@voult/vault-core";
import { ItemIcon } from "./ItemIcon";

/**
 * Left pane: the mockup's Login Items list. Identity leads (username, or the
 * SSO method when the item has no username) and the site label follows.
 */
export function ItemList({
  items,
  matches,
  selectedId,
  onSelect,
  oauthMatches,
  onSuggest,
  busy,
  hasAnyItems,
}: {
  items: VaultItem[];
  matches: LoginMatch[] | null;
  selectedId: string | null;
  onSelect: (id: string) => void;
  oauthMatches: LoginMatch[];
  onSuggest: (id: string) => void;
  busy: boolean;
  hasAnyItems: boolean;
}) {
  const matchIds = new Set((matches ?? []).map((m) => m.id));

  return (
    <aside className="list-pane">
      {oauthMatches.length > 0 && (
        <div className="suggest">
          <span className="suggest__label">Sign in to this site</span>
          {oauthMatches.flatMap((m) =>
            m.sso.map((method) => (
              <button
                key={`${m.id}:${method.provider}:${method.account}`}
                type="button"
                className="suggest__btn"
                disabled={busy}
                title={`Focus the site's Continue with ${ssoProviderLabel(method.provider)} button`}
                onClick={() => onSuggest(m.id)}
              >
                Sign in with {ssoProviderLabel(method.provider)}
                {method.account ? ` · ${method.account}` : ""}
              </button>
            )),
          )}
        </div>
      )}

      <div className="list-scroll">
        {items.length === 0 ? (
          <p className="list-empty">
            {hasAnyItems
              ? "No logins match this view."
              : "No logins yet — save one from a login page."}
          </p>
        ) : (
          <>
            <div className="list-group">
              {items.length} login{items.length === 1 ? "" : "s"}
            </div>
            {items.map((item) => {
              const site = item.site || item.origin || "No site";
              const identity = ssoItemIdentity(item, ssoProviderLabel) || site;
              const selected = item.id === selectedId;
              return (
                <button
                  key={item.id}
                  type="button"
                  className="item"
                  aria-selected={selected}
                  onClick={() => onSelect(item.id)}
                >
                  <ItemIcon item={item} />
                  <span className="item__body">
                    <span className="item__title">{identity}</span>
                    <span className="item__sub">{site}</span>
                  </span>
                  {matchIds.has(item.id) && <span className="item__badge">This site</span>}
                </button>
              );
            })}
          </>
        )}
      </div>
    </aside>
  );
}
