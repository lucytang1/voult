import { Menu, Search, X } from "lucide-react";
import type { Folder, VaultItem } from "@voult/vault-core";
import { FolderSelect } from "./FolderSelect";

/**
 * Top bar: vault menu, search, folder filter. The folder control is the same
 * custom popover listbox as the web app's folder list — icon rows, no counts —
 * rendered by FolderSelect.
 */
export function TopBar({
  query,
  onQueryChange,
  folders,
  items,
  selectedFolderId,
  onFolderChange,
  menuOpen,
  onToggleMenu,
  searchRef,
}: {
  query: string;
  onQueryChange: (value: string) => void;
  folders: Folder[];
  /** Only used to detect whether the Unfiled bucket should be offered. */
  items: VaultItem[];
  selectedFolderId: string | null;
  onFolderChange: (value: string | null) => void;
  menuOpen: boolean;
  onToggleMenu: () => void;
  searchRef: React.RefObject<HTMLInputElement | null>;
}) {
  return (
    <div className="topbar">
      <button
        type="button"
        className={`icon-btn${menuOpen ? " icon-btn--active" : ""}`}
        aria-label="Vault menu"
        aria-haspopup="menu"
        aria-expanded={menuOpen}
        onClick={onToggleMenu}
      >
        <Menu size={17} />
      </button>

      <label className="search">
        <Search size={16} aria-hidden="true" />
        <input
          ref={searchRef}
          type="search"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search logins…"
          spellCheck={false}
          autoComplete="off"
          aria-label="Search logins"
        />
        {query && (
          <button
            type="button"
            className="search__clear"
            aria-label="Clear search"
            onClick={() => {
              onQueryChange("");
              searchRef.current?.focus();
            }}
          >
            <X size={12} />
          </button>
        )}
      </label>

      <FolderSelect
        folders={folders}
        items={items}
        selectedFolderId={selectedFolderId}
        onFolderChange={onFolderChange}
      />
    </div>
  );
}
