// Shadow-DOM suggest dropdown for the content isolate.
//
// Closed ShadowRoot + hand-scoped styles: page CSS/JS cannot restyle or read
// the dropdown, and our styles never leak into the page. Untrusted strings
// (site/username/origin) are rendered via textContent only — never innerHTML.

import type { LoginMatch, SsoSignIn } from "../lib/messaging";
import { ssoProviderLabel } from "./oauth";

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
.voult-rowinner { display: flex; gap: 8px; align-items: center; }
.voult-icon-tile {
  width: 24px; height: 24px; border-radius: 9px; flex-shrink: 0;
  background: #fff; display: inline-flex; align-items: center; justify-content: center;
}
.voult-icon { width: 17px; height: 17px; border-radius: 4px; object-fit: contain; }
.voult-icon-fallback {
  width: 24px; height: 24px; border-radius: 9px; flex-shrink: 0;
  background: #fff; color: #252833; font-size: 11px; font-weight: 700;
  display: inline-flex; align-items: center; justify-content: center;
}
.voult-text { min-width: 0; flex: 1; }
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
 * Row identity for a login, mirroring vault-core's `ssoItemIdentity` — duplicated
 * rather than imported because this bundle must stay a dependency-free IIFE
 * (no zod in every page; see oauth.ts). A provider-only sign-in ("Sign in with
 * GitHub", stored when the vault knew no GitHub account) leads with the method
 * so the row is never blank.
 */
function rowIdentity(username: string, methods: SsoSignIn[]): string {
  if (username) return username;
  const named = methods.filter((s) => s.account.trim()).map((s) => s.account);
  if (named.length > 0) return named.join(" · ");
  const providers = [...new Set(methods.map((s) => s.provider))];
  return providers.length > 0 ? `Sign in with ${providers.map(ssoProviderLabel).join(", ")}` : "";
}

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
    // Keep focus on the login field while selecting a suggestion. If the
    // clicked button takes focus, removing the dropdown below can make the
    // browser move focus to the page's first link (often “Skip to content”).
    row.addEventListener("mousedown", (e) => {
      if (e.button === 0) e.preventDefault();
    });
    const inner = document.createElement("span");
    inner.className = "voult-rowinner";
    // Display-only site icon (worker-supplied http(s) URL). Hidden on load
    // failure so a dead icon never breaks the row; letter tile as fallback.
    const iconUrl = typeof m.faviconUrl === "string" && /^https?:\/\//i.test(m.faviconUrl)
      ? m.faviconUrl
      : null;
    if (iconUrl) {
      const tile = document.createElement("span");
      tile.className = "voult-icon-tile";
      const img = document.createElement("img");
      img.className = "voult-icon";
      img.src = iconUrl;
      img.alt = "";
      img.referrerPolicy = "no-referrer";
      img.addEventListener("error", () => {
        tile.replaceChildren();
        tile.className = "voult-icon-fallback";
        tile.textContent = (m.label || "?").charAt(0).toUpperCase();
      }, { once: true });
      tile.appendChild(img);
      inner.appendChild(tile);
    } else {
      const fallback = document.createElement("span");
      fallback.className = "voult-icon-fallback";
      fallback.textContent = (m.label || "?").charAt(0).toUpperCase();
      inner.appendChild(fallback);
    }
    const text = document.createElement("span");
    text.className = "voult-text";
    const user = document.createElement("span");
    user.className = "voult-user";
    // The account is the identity on every row, password or SSO — an SSO-only
    // login's identity IS its IdP account, so it reads exactly like any other
    // username and "which Google?" is answered rather than left open. A
    // provider-only sign-in has no account to show, so the row names the method.
    const methods = m.sso ?? [];
    const identity = rowIdentity(m.username, methods);
    user.textContent = identity;
    const org = document.createElement("span");
    org.className = "voult-origin";
    // Provider as a suffix, not "Continue with X": tapping the row goes to the
    // site's own button, but what identifies the row is the account. Skipped
    // when the row already fell back to "Sign in with X" — don't say it twice.
    const ssoSuffix = methods.length > 0 && !identity.startsWith("Sign in with")
      ? ` · ${[...new Set(methods.map((s) => ssoProviderLabel(s.provider)))].join(", ")}`
      : "";
    org.textContent = `${m.origin}${ssoSuffix}`;
    if (m.rank === "subdomain") {
      const sub = document.createElement("span");
      sub.className = "voult-sub";
      sub.textContent = "subdomain match";
      org.appendChild(sub);
    }
    text.appendChild(user);
    text.appendChild(org);
    inner.appendChild(text);
    row.appendChild(inner);
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
