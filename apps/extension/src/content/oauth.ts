// OAuth-button discovery for the content isolate.
//
// Finds "Continue with X / Sign in with Y" buttons so the worker can record
// which SSO providers a login page offers, and which one the user clicked.
// Same isolation rules as detect.ts: top frame only (enforced by content.ts),
// visible elements only, no page claims leave except the provider enum.
//
// NOTE: the IdP host map mirrors OAUTH_IDP_HOSTS in
// packages/vault-core/src/schema.ts — duplicated on purpose so this tiny
// content bundle doesn't drag zod into every page. Keep both lists in sync.

import type { SsoProvider } from "../lib/messaging";

export interface OAuthOffer {
  provider: SsoProvider;
  /** Anchor element the user would click. */
  element: HTMLElement;
}

/**
 * Human label for an SSO provider ("Google", "GitHub", …). Lives here (not
 * in lib/messaging) because content scripts must stay a single self-contained
 * IIFE: manifest-declared content scripts load as classic scripts, so any
 * runtime import from a shared module makes Rollup emit a chunk import and
 * Chrome rejects the bundle with "Cannot use import statement outside a
 * module". lib/messaging keeps its own copy for module contexts (popup).
 */
export function ssoProviderLabel(p?: SsoProvider): string {
  switch (p) {
    case "google": return "Google";
    case "github": return "GitHub";
    case "apple": return "Apple";
    case "microsoft": return "Microsoft";
    case "custom": return "SSO";
    default: return "SSO";
  }
}

// Host fragment → provider. Substring match on the link hostname.
const IDP_HOSTS: Record<string, SsoProvider> = {
  "accounts.google.com": "google",
  "github.com": "github",
  "appleid.apple.com": "apple",
  "login.microsoftonline.com": "microsoft",
};

const PROVIDER_NAMES: SsoProvider[] = ["google", "github", "apple", "microsoft"];

// "Continue with Google", "Sign in with GitHub", "Log in with Apple", …
const BUTTON_TEXT_RE =
  /(?:continue with|sign in with|log in with|login with)\s+(google|github|apple|microsoft)\b/i;
// Generic SSO affordance with no named provider ("Continue with SSO",
// "Single sign-on") — recorded as custom.
const GENERIC_SSO_RE = /(?:single sign-?on|\bsso\b)/i;

function isVisible(el: HTMLElement): boolean {
  if (el.hidden) return false;
  if (el instanceof HTMLInputElement && el.disabled) return false;
  const rect = el.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return false;
  const style = window.getComputedStyle(el);
  return style.visibility !== "hidden" && style.display !== "none";
}

/** Provider from a link href's IdP host. Highest confidence — checked first. */
export function providerFromHref(href: string): SsoProvider | null {
  let host = "";
  try {
    host = new URL(href, window.location.href).hostname.toLowerCase();
  } catch {
    return null;
  }
  for (const [fragment, provider] of Object.entries(IDP_HOSTS)) {
    if (host === fragment || host.endsWith(`.${fragment}`)) return provider;
  }
  return null;
}

/** Provider from button/link text. Null when the text names no provider. */
export function providerFromText(text: string): SsoProvider | null {
  const named = BUTTON_TEXT_RE.exec(text.slice(0, 160));
  if (named) return named[1].toLowerCase() as SsoProvider;
  if (GENERIC_SSO_RE.test(text.slice(0, 160))) return "custom";
  return null;
}

/**
 * Which SSO providers this page offers. Scans visible links/buttons once;
 * dedupes by provider (first element wins). Empty on pages with no SSO.
 */
export function findOAuthButtons(root: ParentNode = document): OAuthOffer[] {
  const found = new Map<SsoProvider, HTMLElement>();
  const els = root.querySelectorAll("a[href], button, [role='button']");
  for (const el of els) {
    if (!(el instanceof HTMLElement) || !isVisible(el)) continue;
    // Skip elements inside a password form's submit path — those are
    // password-login submits, not SSO (their text rarely matches anyway).
    let provider: SsoProvider | null = null;
    if (el instanceof HTMLAnchorElement && el.href) {
      provider = providerFromHref(el.href);
    }
    provider ??= providerFromText(el.textContent ?? "");
    // Nested icon-only anchors: check an aria-label as a last resort.
    provider ??= providerFromText(el.getAttribute("aria-label") ?? "");
    if (provider && !found.has(provider)) {
      found.set(provider, el);
      if (found.size >= PROVIDER_NAMES.length + 1) break;
    }
  }
  return [...found].map(([provider, element]) => ({ provider, element }));
}

/**
 * Provider for a click target: walks up to the nearest link/button and
 * resolves it the same way as discovery. Null for ordinary clicks.
 */
export function providerForClick(target: EventTarget | null): SsoProvider | null {
  if (!(target instanceof HTMLElement)) return null;
  const anchor = target.closest("a, button, [role='button']");
  if (!(anchor instanceof HTMLElement)) return null;
  if (anchor instanceof HTMLAnchorElement && anchor.href) {
    const viaHref = providerFromHref(anchor.href);
    if (viaHref) return viaHref;
  }
  return (
    providerFromText(anchor.textContent ?? "") ??
    providerFromText(anchor.getAttribute("aria-label") ?? "")
  );
}

/**
 * Guide the user to the site's own SSO button for a provider: scroll it into
 * view and focus it. Voult never clicks it — the user presses it. Returns
 * false when the page offers no such button (e.g. the layout changed since
 * the marker was saved).
 */
export function highlightOffer(provider: SsoProvider): boolean {
  let offer = findOAuthButtons().find((o) => o.provider === provider);
  // "custom" markers carry no detectable name — point at the first SSO
  // button rather than doing nothing.
  offer ??= provider === "custom" ? findOAuthButtons()[0] : undefined;
  if (!offer) return false;
  const el = offer.element;
  try {
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    el.focus({ preventScroll: true });
  } catch {
    // Best effort only — not all buttons are focusable.
  }
  return true;
}
