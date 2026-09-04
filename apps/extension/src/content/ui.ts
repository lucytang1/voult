// Shadow-DOM suggest dropdown for the content isolate.
//
// Closed ShadowRoot + hand-scoped styles: page CSS/JS cannot restyle or read
// the dropdown, and our styles never leak into the page. Untrusted strings
// (site/username/origin) are rendered via textContent only — never innerHTML.

import type { LoginMatch } from "../lib/messaging";

const STYLE = `
:host { all: initial; }
.voult-dd {
  position: absolute; z-index: 2147483647; min-width: 260px; max-width: 340px;
  background: #17191f; color: #e8eaf0; border: 1px solid #333845;
  border-radius: 10px; box-shadow: 0 8px 28px rgba(0,0,0,.5);
  font: 13px/1.4 system-ui, -apple-system, sans-serif; overflow: hidden;
}
.voult-head {
  padding: 6px 10px; font-size: 11px; color: #9aa0ae;
  border-bottom: 1px solid #262a35;
  display: flex; justify-content: space-between; gap: 8px;
}
.voult-row {
  display: block; width: 100%; text-align: left; background: none; border: 0;
  color: inherit; padding: 8px 10px; cursor: pointer;
}
.voult-row:hover, .voult-row[data-active="true"] { background: #23262e; }
.voult-user { font-weight: 600; display: block; }
.voult-origin { color: #9aa0ae; font-size: 11px; display: block; }
.voult-sub { color: #e0b34e; font-size: 11px; margin-left: 6px; }
`;

export interface DropdownCallbacks {
  onPick: (id: string) => void;
  onDismiss: () => void;
}

let host: HTMLElement | null = null;

function closeDropdown(): void {
  host?.remove();
  host = null;
  document.removeEventListener("pointerdown", onOutside, true);
  document.removeEventListener("keydown", onKey, true);
}

function onOutside(e: Event): void {
  if (host && !host.contains(e.target as Node)) {
    closeDropdown();
    currentCb?.onDismiss();
  }
}

function onKey(e: KeyboardEvent): void {
  if (e.key === "Escape") {
    closeDropdown();
    currentCb?.onDismiss();
  }
}

let currentCb: DropdownCallbacks | null = null;

/**
 * Shows matches anchored under `anchor` (username field preferred, else the
 * password field). No-op when matches is empty — the page stays untouched so
 * locked/empty states are unfingerprintable.
 */
export function showDropdown(
  anchor: HTMLElement,
  matches: LoginMatch[],
  cb: DropdownCallbacks,
): void {
  closeDropdown();
  if (matches.length === 0) return;
  currentCb = cb;

  host = document.createElement("div");
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = STYLE;
  shadow.appendChild(style);

  const box = document.createElement("div");
  box.className = "voult-dd";
  const head = document.createElement("div");
  head.className = "voult-head";
  const title = document.createElement("span");
  title.textContent = "Voult — choose a login";
  head.appendChild(title);
  // Plain-http pages get a visible marker so a filled password on an
  // insecure origin is always a conscious choice, never a surprise.
  if (window.location.protocol === "http:") {
    const insecure = document.createElement("span");
    insecure.textContent = "insecure page";
    head.appendChild(insecure);
  }
  box.appendChild(head);

  for (const m of matches) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "voult-row";
    const user = document.createElement("span");
    user.className = "voult-user";
    user.textContent = m.username;
    const org = document.createElement("span");
    org.className = "voult-origin";
    org.textContent = m.origin;
    if (m.rank === "subdomain") {
      const sub = document.createElement("span");
      sub.className = "voult-sub";
      sub.textContent = "subdomain match";
      org.appendChild(sub);
    }
    row.appendChild(user);
    row.appendChild(org);
    row.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const id = m.id;
      closeDropdown();
      cb.onPick(id);
    });
    box.appendChild(row);
  }

  shadow.appendChild(box);
  document.documentElement.appendChild(host);

  // Anchor under the field; flip above when near the viewport bottom.
  const rect = anchor.getBoundingClientRect();
  const top = rect.bottom + window.scrollY + 4;
  host.style.cssText = `position:absolute;left:${rect.left + window.scrollX}px;top:${top}px;z-index:2147483647;`;

  document.addEventListener("pointerdown", onOutside, true);
  document.addEventListener("keydown", onKey, true);
}

export function dismissDropdown(): void {
  closeDropdown();
}
