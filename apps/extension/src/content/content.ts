// Content-script entry (isolated world).
//
// Top frame only: page JS cannot reach this context, and this context never
// touches anything but the top document (all_frames:false + the guard below).
// Login data enters only after an explicit user gesture (field focus shows
// suggestions; a click fetches exactly one credential), and values are filled
// with trusted input events. Auto-fill on page load never happens.

import { findLoginForms, type LoginForm } from "./detect";
import { findOAuthButtons, highlightOffer, providerForClick, ssoProviderLabel } from "./oauth";
import { fillForm } from "./fill";
import { showDropdown } from "./ui";
import { showSaveBanner, showOAuthSaveBanner } from "./banner";
import type {
  ExtensionMessage,
  FillError,
  FillPayload,
  LoginMatch,
  OAuthSavePrompt,
  SavePrompt,
  SsoProvider,
} from "../lib/messaging";

if (window.top !== window.self) {
  // Belt-and-braces alongside all_frames:false: never run inside iframes, so
  // a malicious embed cannot borrow the top page's credentials.
  throw new Error("voult: refusing to run in a subframe");
}

function send<T>(msg: ExtensionMessage): Promise<T> {
  return chrome.runtime.sendMessage(msg) as Promise<T>;
}

function isErrorResponse(r: unknown): r is { error: string } {
  return !!r && typeof r === "object" && "error" in (r as Record<string, unknown>);
}

async function requestFill(form: LoginForm | null, id: string): Promise<void> {
  const res = await send<FillPayload | FillError>({ type: "FILL_CREDENTIAL", id });
  if (isErrorResponse(res)) {
    // Passwordless SSO holds no secret — the worker names the providers so
    // we can guide the user to the site's own button instead of filling.
    const err = res as FillError;
    const providers = err.ssoProviders ?? (err.ssoProvider ? [err.ssoProvider] : []);
    if (providers.length > 0) highlightOffer(providers[0]);
    return;
  }
  if (form) fillForm(form, res);
}

/** Route one picked suggestion: highlight the site's SSO button for
 *  passwordless logins, fill the form when a password is stored. Logins
 *  carrying both fill the password (SSO stays visible as a badge/row). */
async function pickMatch(form: LoginForm | null, matches: LoginMatch[], id: string): Promise<void> {
  const m = matches.find((x) => x.id === id);
  if (m && !m.hasPassword && m.ssoProviders.length > 0) {
    highlightOffer(m.ssoProviders[0] ?? "custom");
    return;
  }
  if (form) await requestFill(form, id);
}

/** Focus on a login field → suggestions for this tab (if unlocked). */
async function onFieldFocus(e: FocusEvent): Promise<void> {
  const target = e.target as HTMLElement | null;
  if (!(target instanceof HTMLInputElement)) return;
  const forms = findLoginForms();
  const form = forms.find((f) => f.password === target || f.username === target) ?? null;
  const matches = await send<LoginMatch[] | { error: string }>({ type: "QUERY_LOGINS" });
  if (isErrorResponse(matches) || matches.length === 0) return;
  if (form) {
    showDropdown(target, matches, {
      onPick: (id) => void pickMatch(form, matches, id),
      onDismiss: () => undefined,
    });
    return;
  }
  // No password form on this page (SSO/email-only logins like Claude's):
  // focusing the email field still offers stored SSO options. Password-only
  // rows are excluded here — with no form there is nothing to fill.
  if (target.type === "text" || target.type === "email") {
    const oauth = matches.filter((m) => m.ssoProviders.length > 0);
    if (oauth.length === 0) return;
    showDropdown(target, oauth, {
      onPick: (id) => void pickMatch(null, matches, id),
      onDismiss: () => undefined,
    });
  }
}

  // Worker-initiated fills (popup button / keyboard shortcut). Password fills
// stay scoped to forms actually present in this document; passwordless picks
// resolve to a button highlight via the worker's providers error (no form
// needed).
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "VOULT_FILL_ONE") {
    const forms = findLoginForms();
    // Null form is fine: password fills no-op without one, OAuth picks
    // highlight the site's button.
    void requestFill(forms[0] ?? null, String(msg.id)).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg?.type === "VOULT_FILL_BEST") {
    const ids = (msg.ids ?? []) as string[];
    if (ids.length === 0) return false;
    const forms = findLoginForms();
    const form = forms[0] ?? null;
    // Shortcut semantics: exactly one candidate fills immediately (or
    // highlights the SSO button for passwordless logins, no form needed); several
    // candidates open the dropdown on the username (or password) field so the
    // user — not the page — disambiguates.
    if (ids.length === 1) {
      void requestFill(form, ids[0]);
    } else {
      if (!form) return false;
      void (async () => {
        const matches = await send<LoginMatch[] | { error: string }>({ type: "QUERY_LOGINS" });
        if (isErrorResponse(matches)) return;
        const anchor = form.username ?? form.password;
        showDropdown(anchor, matches, {
          onPick: (id) => void pickMatch(form, matches, id),
          onDismiss: () => undefined,
        });
        (anchor as HTMLElement).focus();
      })();
    }
    return false;
  }
  return false;
});

// Delegated at document level so SPA-rendered fields work with no observer.
document.addEventListener("focusin", (e) => {
  void onFieldFocus(e as FocusEvent);
});

// --- OAuth sign-in memory ----------------------------------------------------
// Click on a "Continue with X" button → record the click in the worker (the
// worker stamps the origin from the tab, never from the page). The return
// trip (IdP → app, usually a page with no SSO buttons like /dashboard) is
// detected via reportOAuthPageState below: every page reports on load and SPA
// navigation, and the worker answers whether the journey looks complete and
// unremembered.

function onMaybeOAuthClick(e: MouseEvent): void {
  const provider = providerForClick(e.target);
  if (!provider) return;
  // Fire-and-forget: the click must never block navigation to the IdP.
  const offered = findOAuthButtons().map((o) => o.provider);
  void send<unknown>({ type: "OAUTH_CLICK", provider, offered });
}

// Capture phase so SPA-handled clicks (stopPropagation in bubble) still count.
document.addEventListener("click", onMaybeOAuthClick, true);

/**
 * Report this page's SSO state to the worker. Reports on EVERY page, not just
 * pages with SSO buttons: the return from an IdP lands on an app page like
 * /dashboard with no SSO buttons, and that return is exactly the success
 * signal the worker matches against the in-flight click. One tiny local
 * message per page load; the worker answers prompt:false unless a fresh
 * click, an unlocked vault, and an unremembered provider all line up.
 */
async function reportOAuthPageState(): Promise<void> {
  let offers: SsoProvider[] = [];
  try {
    offers = findOAuthButtons().map((o) => o.provider);
  } catch {
    offers = [];
  }
  let hasLoginForm = false;
  try {
    hasLoginForm = findLoginForms().length > 0;
  } catch {
    hasLoginForm = false;
  }
  const res = await send<OAuthSavePrompt | { error: string }>({
    type: "OAUTH_PAGE_STATE",
    offers,
    hasLoginForm,
    path: window.location.pathname,
  });
  if (isErrorResponse(res) || !res.prompt) return;
  const { provider, origin } = res;
  showOAuthSaveBanner(ssoProviderLabel(provider), origin, {
    onConfirm: () => {
      void send<{ saved: boolean }>({ type: "SAVE_OAUTH_DECISION", provider });
    },
    onNever: () => {
      void send({ type: "NEVER_ORIGIN" });
    },
    onDismiss: () => undefined,
  });
}

// Initial report (content runs at document_idle, DOM is ready).
void reportOAuthPageState();

// SPA navigations don't reload the content script — re-report on pushState /
// replaceState / popstate so in-app returns from the IdP are still caught.
for (const method of ["pushState", "replaceState"] as const) {
  const orig = history[method];
  history[method] = function (...args: Parameters<History[typeof method]>) {
    const ret = (orig as (...a: Parameters<History[typeof method]>) => void).apply(this, args);
    void reportOAuthPageState();
    return ret;
  };
}
window.addEventListener("popstate", () => {
  void reportOAuthPageState();
});

// --- M2: offer to save -------------------------------------------------------
// Capture runs once per form per page (WeakSet): submit in the capture phase
// (submit events don't bubble, but capture sees them including SPA handlers),
// plus a beforeunload fallback for XHR logins with no navigation. Heuristic
// gate: password field holds ≥4 chars. Values are read once and sent to the
// worker, which dedupes against the unlocked cache and answers prompt or not.

const handledForms = new WeakSet<HTMLFormElement>();
const handledOrphans = new WeakSet<HTMLInputElement>();

function readCredential(form: LoginForm): { username: string; password: string } | null {
  const password = form.password.value;
  if (!password || password.length < 4) return null;
  return { username: form.username?.value ?? "", password };
}

async function handleCapture(form: LoginForm): Promise<void> {
  const creds = readCredential(form);
  if (!creds || !creds.username) return;
  const res = await send<SavePrompt | { error: string }>({ type: "LOGIN_CANDIDATE", ...creds });
  if (isErrorResponse(res) || !res.prompt) return;
  const { mode, origin, username } = res;
  showSaveBanner(mode, origin, username, {
    onConfirm: () => {
      void send<{ saved: boolean }>({
        type: "SAVE_DECISION",
        username: creds.username,
        password: creds.password,
        mode,
      });
    },
    onNever: () => {
      void send({ type: "NEVER_ORIGIN" });
    },
    onDismiss: () => undefined,
  });
}

document.addEventListener(
  "submit",
  (e) => {
    const target = e.target;
    if (!(target instanceof HTMLFormElement)) return;
    if (handledForms.has(target)) return;
    handledForms.add(target);
    const forms = findLoginForms();
    const match = forms.find((f) => f.password.form === target);
    const form = match ?? null;
    if (!form) return;
    // Don't delay navigation for the worker round-trip.
    void handleCapture(form);
  },
  true,
);

window.addEventListener("beforeunload", () => {
  for (const form of findLoginForms()) {
    const scope = form.password.form;
    if (scope) {
      if (handledForms.has(scope)) continue;
      handledForms.add(scope);
    } else {
      if (handledOrphans.has(form.password)) continue;
      handledOrphans.add(form.password);
    }
    // Best effort only — the page is going away; no banner, just the capture.
    // navigator.sendMessage is unavailable; fire-and-forget runtime message.
    const creds = readCredential(form);
    if (!creds || !creds.username) continue;
    void chrome.runtime.sendMessage({ type: "LOGIN_CANDIDATE", ...creds });
  }
});
