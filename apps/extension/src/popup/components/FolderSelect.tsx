import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, Folder as FolderIcon } from "lucide-react";
import { itemsInFolder, UNFILED_LABEL } from "@voult/vault-core";
import type { Folder, VaultItem } from "@voult/vault-core";

/**
 * Folder filter: a custom popover listbox styled after the web app's folder
 * list — icon + name rows with the active row highlighted. A native `<select>`
 * cannot be styled into that shape (the OS-owned dropdown ignores the design
 * tokens), so the list is rendered here with the same transparent-backdrop
 * pattern as the vault menu. Item counts are deliberately omitted: the list is
 * a filter, not a statistics view.
 *
 * Rows take real focus so keyboard support works without position math:
 * arrows move, Enter/Space pick, Tab/Escape dismiss and focus returns to the
 * trigger.
 */
export function FolderSelect({
  folders,
  items,
  selectedFolderId,
  onFolderChange,
}: {
  folders: Folder[];
  items: VaultItem[];
  selectedFolderId: string | null;
  onFolderChange: (value: string | null) => void;
}) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);

  // "All folders" first, then the real folders, then Unfiled — which is only
  // offered when it would show something (same rule as the web sidebar) or
  // when it is the active filter and must not vanish under the selection.
  const options = useMemo(() => {
    const list: { value: string | null; label: string }[] = [
      { value: null, label: "All folders" },
    ];
    for (const folder of folders) list.push({ value: folder.id, label: folder.name });
    const hasUnfiled = itemsInFolder(items, folders, null).length > 0;
    if (hasUnfiled || selectedFolderId === "unfiled") {
      list.push({ value: "unfiled", label: UNFILED_LABEL });
    }
    return list;
  }, [folders, items, selectedFolderId]);

  // A selected folder that just disappeared still labels the closed control
  // until the root's fallback effect resets the selection.
  const activeLabel =
    options.find((option) => option.value === selectedFolderId)?.label ?? "All folders";

  useEffect(() => {
    if (!open) return;
    // Focus the active row (or the first row) so arrows work immediately.
    const startIndex = Math.max(
      0,
      options.findIndex((option) => option.value === selectedFolderId),
    );
    optionRefs.current[startIndex]?.focus();
  }, [open, options, selectedFolderId]);

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) triggerRef.current?.focus();
  };

  const pick = (value: string | null) => {
    onFolderChange(value);
    close(true);
  };

  if (!open) {
    return (
      <div className="folder-select">
        <button
          ref={triggerRef}
          type="button"
          className="folder-select__trigger"
          aria-label="Filter by folder"
          aria-haspopup="listbox"
          aria-expanded={false}
          onClick={() => setOpen(true)}
        >
          <FolderIcon size={15} aria-hidden="true" />
          <span className="folder-select__label">{activeLabel}</span>
          <ChevronDown size={14} className="folder-select__chevron" aria-hidden="true" />
        </button>
      </div>
    );
  }

  return (
    <div
      className="folder-select"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          close(true);
        } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const dir = e.key === "ArrowDown" ? 1 : -1;
          const current = optionRefs.current.indexOf(
            document.activeElement as HTMLButtonElement,
          );
          const next = Math.max(
            0,
            Math.min(options.length - 1, (current === -1 ? 0 : current) + dir),
          );
          optionRefs.current[next]?.focus();
        }
      }}
    >
      <button
        ref={triggerRef}
        type="button"
        className="folder-select__trigger"
        aria-label="Filter by folder"
        aria-haspopup="listbox"
        aria-expanded
        tabIndex={-1}
        onClick={() => close(true)}
      >
        <FolderIcon size={15} aria-hidden="true" />
        <span className="folder-select__label">{activeLabel}</span>
        <ChevronDown
          size={14}
          className="folder-select__chevron folder-select__chevron--open"
          aria-hidden="true"
        />
      </button>

      <button
        type="button"
        className="menu-backdrop"
        aria-label="Close folder filter"
        tabIndex={-1}
        onClick={() => close(false)}
      />
      <div className="folder-menu" role="listbox" aria-label="Folders">
        {options.map((option, index) => {
          const selected = option.value === selectedFolderId;
          return (
            <button
              key={option.value ?? "all"}
              ref={(node) => {
                optionRefs.current[index] = node;
              }}
              type="button"
              role="option"
              aria-selected={selected}
              className={`folder-menu__item${selected ? " folder-menu__item--selected" : ""}`}
              onClick={() => pick(option.value)}
            >
              <FolderIcon size={15} aria-hidden="true" />
              <span className="folder-menu__label">{option.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
