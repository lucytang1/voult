// Page-anchored save/update card for the content isolate.
//
// Closed ShadowRoot, textContent-only rendering for anything the page controls
// (same isolation rules as the suggest dropdown). Dismiss is the default
// outcome: the card never auto-saves, and ignoring it changes nothing.
//
// The look mirrors the popup's design system (apps/extension/src/popup/popup.css):
// the same plum palette, hairline / hairline-accent edges, icon tile and
// 9/12/16/18px radii, repeated here because a content script ships as one
// classic IIFE and cannot import the popup's stylesheet. Keep the two in step
// when the palette moves. The font is the platform UI stack rather than Inter:
// a page cannot load the extension's woff2 (no web_accessible_resources entry),
// and adding one would announce the extension in every site's network log.

import type { SaveFolder } from "../lib/messaging";

export interface BannerCallbacks {
  /** `folderId` is the destination picked in the card; null means Unfiled. */
  onConfirm: (folderId: string | null) => void;
  onNever: () => void;
  onDismiss: () => void;
}

export interface SaveCardOptions {
  mode: "save" | "update";
  origin: string;
  username: string;
  /** Vault label — display only (the destination control is the folder). */
  vaultName: string | null;
  folders: SaveFolder[];
  /** Preselected destination; null = Unfiled. */
  folderId: string | null;
  /** Display-only site icon, already validated by the worker. */
  faviconUrl: string | null;
}

export interface OAuthCardOptions {
  providerLabel: string;
  origin: string;
  /** Accounts this vault already knows for the provider (may be empty). */
  accounts: string[];
  vaultName: string | null;
  folders: SaveFolder[];
  folderId: string | null;
  faviconUrl: string | null;
}

/**
 * OAuth variant: `onConfirm` receives the account the user picked from the
 * vault's known accounts for that provider, or "" when the vault knows none and
 * the sign-in is stored provider-only.
 */
export interface OAuthBannerCallbacks {
  onConfirm: (account: string, folderId: string | null) => void;
  onNever: () => void;
  onDismiss: () => void;
}

// Mirrors the popup tokens (--panel, --surface, --hairline, --hairline-accent,
// --accent, --accent-line, --accent-hover, --accent-text, --text, --muted,
// --danger, --icon-tile). accent-line is the only accent bright enough to read
// as an edge on this ground, so it carries every control outline.
const STYLE = `
:host { all: initial; }
.voult-card {
  position: fixed; top: 18px; right: 18px; z-index: 2147483647;
  width: 340px; padding: 12px;
  color: #f2f4f7;
  border: 1px solid #352235; border-radius: 18px;
  background:
    radial-gradient(120% 120% at 12% 0%, rgba(124, 42, 99, 0.22), transparent 58%),
    #160d1b;
  box-shadow: 0 18px 48px rgba(0, 0, 0, 0.55);
  font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
}
.voult-card *, .voult-card *::before, .voult-card *::after { box-sizing: border-box; }
.voult-card button {
  font: inherit; color: inherit; cursor: pointer;
  -webkit-tap-highlight-color: transparent;
}
/* The page's UA focus ring is a blue outline that belongs to no palette here;
   the accent ring replaces it and only appears for keyboard focus. */
.voult-card button:focus { outline: none; }
.voult-card button:focus-visible { box-shadow: 0 0 0 2px rgba(124, 42, 99, 0.6); }
.voult-card ::-webkit-scrollbar { width: 8px; }
.voult-card ::-webkit-scrollbar-thumb {
  background: #2c2333; border-radius: 99px;
  border: 2px solid transparent; background-clip: content-box;
}

/* --- Header: brand mark, destination pill, overflow, close ---------------- */
.voult-head { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.voult-mark {
  display: inline-flex; align-items: center; justify-content: center; flex: 0 0 auto;
  width: 28px; height: 28px; border-radius: 9px;
  border: 1px solid #7c2a63; color: #f2f4f7;
  background: linear-gradient(150deg, #7c2a63 0%, #3f072c 100%);
}
.voult-mark svg { width: 15px; height: 15px; }
.voult-dest {
  display: inline-flex; align-items: center; gap: 7px;
  min-width: 0; height: 30px; padding: 0 11px;
  border: 1px solid #34343a; border-radius: 999px;
  background: #1a1a1b; color: #f2f4f7;
  font-size: 12.5px; font-weight: 600;
  transition: background 120ms ease, border-color 120ms ease;
}
.voult-dest:hover:not(:disabled) { background: #2a1a30; border-color: #7c2a63; }
.voult-dest[aria-expanded="true"] { background: #2a1a30; border-color: #7c2a63; }
/* Update mode: the login already lives in a folder, so the pill is a label —
   moving an entry is an editing action, not part of "update this password?".
   It is a plain span, and the hover rule above is neutralised explicitly
   because it is more specific than a single class. */
.voult-dest--fixed,
.voult-dest--fixed:hover {
  cursor: default;
  background: transparent;
  border-color: #352235;
}
.voult-dest svg { width: 14px; height: 14px; flex: 0 0 auto; }
.voult-dest__name {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 96px;
  text-align: left;
}
.voult-chevron { transition: transform 120ms ease; }
.voult-dest[aria-expanded="true"] .voult-chevron { transform: rotate(180deg); }
.voult-round {
  display: inline-flex; align-items: center; justify-content: center; flex: 0 0 auto;
  width: 30px; height: 30px; padding: 0;
  border: 1px solid #34343a; border-radius: 999px;
  background: #1a1a1b; color: #f2f4f7;
  transition: background 120ms ease, border-color 120ms ease;
}
.voult-round:hover { background: #2a1a30; border-color: #7c2a63; }
.voult-round--close { margin-left: auto; }
.voult-round svg { width: 15px; height: 15px; }

/* --- Fields: one card, hairline-separated rows ---------------------------- */
.voult-fields {
  overflow: hidden;
  border: 1px solid #352235; border-radius: 16px;
  background: #1a1a1b;
}
.voult-row { display: flex; align-items: center; gap: 11px; padding: 10px 12px; }
.voult-row + .voult-row { border-top: 1px solid #2a2630; }
.voult-row__body { flex: 1; min-width: 0; }
.voult-label {
  display: block; margin-bottom: 2px;
  color: #7e8590; font-size: 10px; font-weight: 600;
  letter-spacing: 0.07em; text-transform: uppercase;
}
.voult-value {
  display: block; overflow: hidden;
  font-size: 13px; font-weight: 600;
  text-overflow: ellipsis; white-space: nowrap;
}
.voult-value--title { font-size: 14.5px; font-weight: 650; letter-spacing: -0.01em; }
.voult-value--muted { color: #7e8590; font-weight: 500; }
.voult-value--secret { font-weight: 500; letter-spacing: 0.1em; }

.voult-tile {
  position: relative; display: inline-flex; align-items: center; justify-content: center;
  flex: 0 0 auto; width: 38px; height: 38px; overflow: hidden;
  border-radius: 12px; background: #f4f2f5; color: #252833;
  font-size: 15px; font-weight: 700;
}
.voult-tile img {
  position: absolute; inset: 0; width: 22px; height: 22px; margin: auto;
  border-radius: 4px; object-fit: contain;
}

/* Account chooser (OAuth variant): the row is the choice, the footer commits. */
.voult-accounts { display: flex; flex-direction: column; gap: 4px; padding: 10px 12px; }
.voult-accounts__label {
  display: block; margin: 0 0 2px;
  color: #7e8590; font-size: 10px; font-weight: 600;
  letter-spacing: 0.07em; text-transform: uppercase;
}
.voult-account {
  display: flex; align-items: center; gap: 8px; width: 100%;
  padding: 8px 10px; text-align: left;
  border: 1px solid #34343a; border-radius: 10px;
  background: #18191a; color: #f2f4f7;
  font-size: 12.5px;
}
.voult-account:hover { border-color: #7c2a63; }
.voult-account[aria-checked="true"] {
  border-color: rgba(124, 42, 99, 0.55);
  background: rgba(124, 42, 99, 0.18);
}
.voult-account__dot {
  flex: 0 0 auto; width: 14px; height: 14px; border-radius: 999px;
  border: 1px solid #34343a; background: transparent;
}
.voult-account[aria-checked="true"] .voult-account__dot {
  border-color: #d89ac6; background: #d89ac6;
  box-shadow: inset 0 0 0 2px #160d1b;
}
.voult-account__name {
  flex: 1; min-width: 0; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap;
}
.voult-hint {
  margin: 0; padding: 0 12px 10px;
  color: #7e8590; font-size: 10.5px; line-height: 1.5;
}

/* --- Footer --------------------------------------------------------------- */
.voult-foot { display: flex; gap: 8px; margin-top: 10px; }
.voult-btn {
  height: 36px; padding: 0 18px;
  border-radius: 999px; font-size: 12.5px; font-weight: 600;
  transition: background 120ms ease, border-color 120ms ease;
}
.voult-btn--ghost { flex: 0 0 auto; background: transparent; border: 1px solid #34343a; }
.voult-btn--ghost:hover { background: #1a1a1b; border-color: #7c2a63; }
/* The mockup's light-lavender CTA maps to the accent, but a flat #3f072c fill
   on this panel reads dimmer than the outlined "Not now" and inverts the
   hierarchy. The mark's accent-line → accent gradient (already this card's
   motif) plus an accent-text edge restores the primary's weight without
   leaving the palette. */
.voult-btn--primary {
  flex: 1;
  border: 1px solid rgba(216, 154, 198, 0.42);
  background: linear-gradient(180deg, #7c2a63 0%, #3f072c 100%);
}
.voult-btn--primary:hover {
  border-color: rgba(216, 154, 198, 0.62);
  background: linear-gradient(180deg, #8d3272 0%, #57103e 100%);
}

/* --- Popovers (destination + overflow menu) ------------------------------- */
.voult-pop {
  position: absolute; z-index: 2; padding: 6px;
  border: 1px solid #34343a; border-radius: 14px;
  background: #160d1b;
  box-shadow: 0 18px 48px rgba(0, 0, 0, 0.58);
}
.voult-pop--dest {
  top: 46px; left: 40px; min-width: 186px; max-width: 250px;
  max-height: 232px; overflow-y: auto;
}
.voult-pop--menu { top: 46px; right: 12px; min-width: 208px; }
.voult-pop__item {
  display: flex; align-items: center; gap: 9px; width: 100%;
  padding: 8px 9px; text-align: left;
  border: 1px solid transparent; border-radius: 9px;
  background: transparent; color: #f2f4f7; font-size: 12.5px;
}
.voult-pop__item:hover { background: #1a1a1b; }
.voult-pop__item--selected {
  border-color: rgba(124, 42, 99, 0.4);
  background: rgba(124, 42, 99, 0.18);
}
.voult-pop__item--danger { color: #ff8f8f; }
.voult-pop__name {
  flex: 1; min-width: 0; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap;
}
.voult-pop__item svg { width: 15px; height: 15px; flex: 0 0 auto; }
.voult-pop__item:not(.voult-pop__item--selected) > .voult-check { visibility: hidden; }
`;

// Static icon markup only — no page-controlled string ever reaches innerHTML.
function svg(paths: string): string {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
}
const ICONS = {
  shield: svg(
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
  ),
  folder: svg(
    '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
  ),
  chevron: svg('<path d="m6 9 6 6 6-6"/>'),
  kebab: svg(
    '<circle cx="12" cy="5" r="1.7" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.7" fill="currentColor" stroke="none"/><circle cx="12" cy="19" r="1.7" fill="currentColor" stroke="none"/>',
  ),
  close: svg('<path d="M18 6 6 18M6 6l12 12"/>'),
  check: svg('<path d="M20 6 9 17l-5-5"/>'),
};

let host: HTMLElement | null = null;

/** The one open popover (destination or overflow), or null. */
let activePopover: { close: (refocus?: boolean) => void } | null = null;

function teardown(): void {
  activePopover?.close();
  host?.remove();
  host = null;
}

/** A host element with a closed shadow root carrying this card's styles. */
function mount(): ShadowRoot {
  host = document.createElement("div");
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = STYLE;
  shadow.appendChild(style);
  return shadow;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function icon(markup: string, className?: string): HTMLSpanElement {
  const span = el("span", className);
  span.setAttribute("aria-hidden", "true");
  span.innerHTML = markup;
  return span;
}

/** Host of an origin for display: no scheme, no `www.` (label, not identity). */
function originLabel(origin: string): string {
  try {
    return new URL(origin).hostname.replace(/^www\./, "");
  } catch {
    return origin;
  }
}

/**
 * The site tile: letter fallback underneath, favicon layered on top. A dead
 * icon simply removes itself, so a broken favicon can never blank the row.
 */
function iconTile(faviconUrl: string | null, label: string): HTMLElement {
  const tile = el("span", "voult-tile");
  tile.appendChild(el("span", undefined, (label || "?").charAt(0).toUpperCase()));
  if (faviconUrl && /^https?:\/\//i.test(faviconUrl)) {
    const img = document.createElement("img");
    img.src = faviconUrl;
    img.alt = "";
    img.referrerPolicy = "no-referrer";
    img.addEventListener("error", () => img.remove(), { once: true });
    tile.appendChild(img);
  }
  return tile;
}

function fieldRow(
  label: string,
  value: string,
  opts: { title?: boolean; muted?: boolean; secret?: boolean; tile?: HTMLElement } = {},
): HTMLElement {
  const row = el("div", "voult-row");
  if (opts.tile) row.appendChild(opts.tile);
  const body = el("div", "voult-row__body");
  body.appendChild(el("span", "voult-label", label));
  const valueClass = [
    "voult-value",
    opts.title ? "voult-value--title" : "",
    opts.muted ? "voult-value--muted" : "",
    opts.secret ? "voult-value--secret" : "",
  ]
    .filter(Boolean)
    .join(" ");
  // Page-derived strings (origin, username) go in through textContent only.
  body.appendChild(el("span", valueClass, value));
  row.appendChild(body);
  return row;
}

/** Destination label: known folder name, else the Unfiled bucket. */
function folderLabel(folders: SaveFolder[], folderId: string | null): string {
  if (!folderId) return "Unfiled";
  return folders.find((f) => f.id === folderId)?.name ?? "Unfiled";
}

/**
 * Opens a popover anchored inside the card. Only one can be open; a click
 * anywhere outside closes it without stealing focus back from the page, while
 * picking a row or pressing Escape returns focus to the trigger.
 */
function popover(
  parent: HTMLElement,
  className: string,
  trigger: HTMLElement,
  onClose: () => void,
): { panel: HTMLDivElement; close: (refocus?: boolean) => void } {
  activePopover?.close();
  const panel = el("div", `voult-pop ${className}`);
  parent.appendChild(panel);
  const api = {
    close: (refocus = false) => {
      if (activePopover !== api) return;
      activePopover = null;
      panel.remove();
      document.removeEventListener("pointerdown", onOutside, true);
      onClose();
      if (refocus) trigger.focus();
    },
  };
  const onOutside = (e: Event) => {
    if (!panel.contains(e.target as Node)) api.close();
  };
  document.addEventListener("pointerdown", onOutside, true);
  activePopover = api;
  return { panel, close: api.close };
}

/**
 * Destination control (the mockup's "Personal ▾" pill): shows where the login
 * will be filed and lets the user file it somewhere else.
 */
function destinationControl(opts: {
  card: HTMLElement;
  folders: SaveFolder[];
  folderId: string | null;
  vaultName: string | null;
  readOnly: boolean;
}): { node: HTMLElement; value: () => string | null } {
  // Only a folder that still exists is a valid destination; a dangling id from
  // another device falls back to Unfiled, which is where the write path would
  // leave it anyway.
  let selected: string | null =
    opts.folderId && opts.folders.some((f) => f.id === opts.folderId) ? opts.folderId : null;

  // A read-only destination is a label, not a disabled button: it must not take
  // focus or promise a picker it cannot open.
  const node: HTMLElement = opts.readOnly
    ? el("span", "voult-dest voult-dest--fixed")
    : el("button", "voult-dest");
  if (node instanceof HTMLButtonElement) node.type = "button";
  const name = el("span", "voult-dest__name");
  node.appendChild(icon(ICONS.folder));
  node.appendChild(name);

  const render = () => {
    name.textContent = folderLabel(opts.folders, selected);
    // Names the place in full (the pill truncates, the tooltip does not).
    const path = opts.vaultName
      ? `${opts.vaultName} › ${folderLabel(opts.folders, selected)}`
      : folderLabel(opts.folders, selected);
    node.title = opts.readOnly ? `Saved in ${path}` : `Save in ${path}`;
  };
  render();

  if (!opts.readOnly) {
    const button = node as HTMLButtonElement;
    button.setAttribute("aria-haspopup", "listbox");
    button.setAttribute("aria-expanded", "false");
    button.appendChild(icon(ICONS.chevron, "voult-chevron"));
    button.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (button.getAttribute("aria-expanded") === "true") {
        activePopover?.close(true);
        return;
      }
      button.setAttribute("aria-expanded", "true");
      const { panel, close } = popover(opts.card, "voult-pop--dest", button, () =>
        button.setAttribute("aria-expanded", "false"),
      );
      panel.setAttribute("role", "listbox");
      panel.setAttribute("aria-label", "Save in folder");
      // Unfiled is always offered: "no folder" is a real bucket in the vault,
      // not an error state, and must stay reachable when no folders exist.
      const options: { id: string | null; label: string }[] = [
        ...opts.folders.map((f) => ({ id: f.id, label: f.name })),
        { id: null, label: "Unfiled" },
      ];
      for (const option of options) {
        const row = el(
          "button",
          `voult-pop__item${option.id === selected ? " voult-pop__item--selected" : ""}`,
        );
        row.type = "button";
        row.setAttribute("role", "option");
        row.setAttribute("aria-selected", String(option.id === selected));
        row.appendChild(icon(ICONS.folder));
        row.appendChild(el("span", "voult-pop__name", option.label));
        row.appendChild(icon(ICONS.check, "voult-check"));
        row.addEventListener("click", (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          selected = option.id;
          render();
          close(true);
        });
        panel.appendChild(row);
      }
      // Focus the current row so arrows/Enter work without reaching for the mouse.
      (panel.querySelector<HTMLElement>('[aria-selected="true"]') ??
        panel.querySelector<HTMLElement>("button"))?.focus();
    });
  }

  return { node, value: () => selected };
}

/**
 * Card shell shared by both variants: brand mark, destination pill, overflow
 * menu (just "Never for this site" — a save prompt should not grow a settings
 * surface) and the close button. Variants fill in the body and the primary
 * action.
 */
function buildShell(
  opts: {
    vaultName: string | null;
    folders: SaveFolder[];
    folderId: string | null;
    readOnlyDest: boolean;
    ariaLabel: string;
  },
  cbs: { onNever: () => void; onDismiss: () => void },
): {
  card: HTMLElement;
  body: HTMLElement;
  footer: HTMLElement;
  destination: () => string | null;
} {
  const card = el("div", "voult-card");
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-label", opts.ariaLabel);

  // Escape closes an open popover only. It must not dismiss the card: a stray
  // Escape in the page would then silently resolve (and clear) a pending save.
  card.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && activePopover) {
      e.stopPropagation();
      activePopover.close(true);
    }
  });

  const head = el("div", "voult-head");
  const mark = el("span", "voult-mark");
  mark.innerHTML = ICONS.shield; // static icon markup
  head.appendChild(mark);

  const destination = destinationControl({
    card,
    folders: opts.folders,
    folderId: opts.folderId,
    vaultName: opts.vaultName,
    readOnly: opts.readOnlyDest,
  });
  head.appendChild(destination.node);

  const more = el("button", "voult-round");
  more.type = "button";
  more.setAttribute("aria-label", "More save options");
  more.setAttribute("aria-haspopup", "menu");
  more.setAttribute("aria-expanded", "false");
  more.appendChild(icon(ICONS.kebab));
  more.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (more.getAttribute("aria-expanded") === "true") {
      activePopover?.close(true);
      return;
    }
    more.setAttribute("aria-expanded", "true");
    const { panel, close: closeMenu } = popover(card, "voult-pop--menu", more, () =>
      more.setAttribute("aria-expanded", "false"),
    );
    panel.setAttribute("role", "menu");
    const never = el("button", "voult-pop__item voult-pop__item--danger", "Never for this site");
    never.type = "button";
    never.setAttribute("role", "menuitem");
    never.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      closeMenu();
      teardown();
      cbs.onNever();
    });
    panel.appendChild(never);
    never.focus();
  });

  const closeBtn = el("button", "voult-round voult-round--close");
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Not now");
  closeBtn.appendChild(icon(ICONS.close));
  closeBtn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    teardown();
    cbs.onDismiss();
  });

  head.appendChild(more);
  head.appendChild(closeBtn);

  const body = el("div");
  const footer = el("div", "voult-foot");
  card.appendChild(head);
  card.appendChild(body);
  card.appendChild(footer);

  return { card, body, footer, destination: destination.value };
}

function ghostButton(label: string, run: () => void): HTMLButtonElement {
  const button = el("button", "voult-btn voult-btn--ghost", label);
  button.type = "button";
  button.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    teardown();
    run();
  });
  return button;
}

/**
 * Shows the save/update card. Only one card at a time; showing a new one
 * replaces the old. The password is never displayed or received here — the
 * card only says that one is included.
 */
export function showSaveBanner(opts: SaveCardOptions, cb: BannerCallbacks): void {
  teardown();
  const isSave = opts.mode === "save";
  const shell = buildShell(
    {
      vaultName: opts.vaultName,
      folders: opts.folders,
      folderId: opts.folderId,
      // An update writes into the item that already exists (and only the
      // password / icon / SSO fields change), so the destination is fixed.
      readOnlyDest: !isSave,
      ariaLabel: isSave ? "Save this login in Voult?" : "Update this saved login?",
    },
    { onNever: cb.onNever, onDismiss: cb.onDismiss },
  );

  const fields = el("div", "voult-fields");
  fields.appendChild(
    fieldRow("Title", originLabel(opts.origin), {
      title: true,
      tile: iconTile(opts.faviconUrl, originLabel(opts.origin)),
    }),
  );
  fields.appendChild(
    fieldRow("Username/email", opts.username || "—", { muted: !opts.username }),
  );
  // A fixed mask, not the real length: the post-redirect page never holds the
  // password, so a length-accurate row would be a lie on exactly the path that
  // needs this card most.
  fields.appendChild(fieldRow("Password", "•".repeat(10), { secret: true }));
  shell.body.appendChild(fields);

  const primary = el("button", "voult-btn voult-btn--primary", isSave ? "Add" : "Update");
  primary.type = "button";
  primary.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    const folderId = shell.destination();
    teardown();
    cb.onConfirm(folderId);
  });
  shell.footer.appendChild(ghostButton("Not now", cb.onDismiss));
  shell.footer.appendChild(primary);

  const shadow = mount();
  shadow.appendChild(shell.card);
  document.documentElement.appendChild(host!);
}

export function dismissSaveBanner(): void {
  teardown();
}

/**
 * OAuth variant: "Signed in with Google?" — no secret exists to display, and we
 * cannot observe the IdP's assertion, so we never assert an account either.
 * Instead the card offers the accounts this vault already knows for that
 * provider and the user picks one; with none known, the sign-in is stored
 * provider-only ("Sign in with Google").
 *
 * Same one-card-at-a-time and dismiss-default semantics as the password card.
 * A row is a *choice* and the footer commits: one deliberate Add is harder to
 * hit by accident than a row that saves the moment it is clicked.
 */
export function showOAuthSaveBanner(opts: OAuthCardOptions, cb: OAuthBannerCallbacks): void {
  teardown();
  const shell = buildShell(
    {
      vaultName: opts.vaultName,
      folders: opts.folders,
      folderId: opts.folderId,
      readOnlyDest: false,
      ariaLabel: `Save a "Sign in with ${opts.providerLabel}" login in Voult?`,
    },
    { onNever: cb.onNever, onDismiss: cb.onDismiss },
  );

  const fields = el("div", "voult-fields");
  fields.appendChild(
    fieldRow("Title", originLabel(opts.origin), {
      title: true,
      tile: iconTile(opts.faviconUrl, originLabel(opts.origin)),
    }),
  );
  fields.appendChild(fieldRow("Method", `Sign in with ${opts.providerLabel}`));
  shell.body.appendChild(fields);

  // "" = provider-only: the honest answer when the vault knows no account.
  let chosen = opts.accounts[0] ?? "";

  if (opts.accounts.length > 0) {
    const group = el("div");
    group.setAttribute("role", "radiogroup");
    group.setAttribute("aria-label", `Which ${opts.providerLabel} account?`);
    const chooser = el("div", "voult-accounts");
    chooser.appendChild(
      el("span", "voult-accounts__label", `Which ${opts.providerLabel} account?`),
    );
    const rows: HTMLButtonElement[] = [];
    for (const account of opts.accounts) {
      const row = el("button", "voult-account");
      row.type = "button";
      row.setAttribute("role", "radio");
      row.setAttribute("aria-checked", String(account === chosen));
      row.appendChild(el("span", "voult-account__dot"));
      // Accounts come from the vault, but are still rendered as text only.
      const label = el("span", "voult-account__name", account);
      label.title = account;
      row.appendChild(label);
      row.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        chosen = account;
        for (const other of rows) {
          other.setAttribute("aria-checked", String(other === row));
        }
      });
      rows.push(row);
      chooser.appendChild(row);
    }
    group.appendChild(chooser);
    shell.body.appendChild(group);
    shell.body.appendChild(
      el(
        "p",
        "voult-hint",
        "Only accounts already in your vault are listed — Voult cannot see which account was used.",
      ),
    );
  } else {
    shell.body.appendChild(
      el(
        "p",
        "voult-hint",
        `No ${opts.providerLabel} account in your vault yet — this saves the sign-in method only.`,
      ),
    );
  }

  const primary = el("button", "voult-btn voult-btn--primary", "Add");
  primary.type = "button";
  primary.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    const account = chosen;
    const folderId = shell.destination();
    teardown();
    cb.onConfirm(account, folderId);
  });
  shell.footer.appendChild(ghostButton("Not now", cb.onDismiss));
  shell.footer.appendChild(primary);

  const shadow = mount();
  shadow.appendChild(shell.card);
  document.documentElement.appendChild(host!);
}
