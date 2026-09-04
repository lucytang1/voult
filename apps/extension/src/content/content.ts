// Content-script entry (isolated world).
//
// Top frame only: page JS cannot reach this context, and this context never
// touches anything but the top document (all_frames:false + the guard below).
// Login data enters only after an explicit user gesture (field focus shows
// suggestions; a click fetches exactly one credential), and values are filled
// with trusted input events. Auto-fill on page load never happens.

import { findLoginForms, type LoginForm } from "./detect";
import { fillForm } from "./fill";
import { showDropdown } from "./ui";
import { showSaveBanner } from "./banner";
import type {
  ExtensionMessage,
  FillPayload,
  LoginMatch,
  SavePrompt,
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

async function requestFill(form: LoginForm, id: string): Promise<void> {
  const res = await send<FillPayload | { error: string }>({ type: "FILL_CREDENTIAL", id });
  if (isErrorResponse(res)) return;
  fillForm(form, res);
}

/** Focus/click on a login field → suggestions for this tab (if unlocked). */
async function onFieldFocus(e: FocusEvent): Promise<void> {
  const target = e.target as HTMLElement | null;
  if (!(target instanceof HTMLInputElement)) return;
  const forms = findLoginForms();
  const form = forms.find((f) => f.password === target || f.username === target);
  if (!form) return;
  const matches = await send<LoginMatch[] | { error: string }>({ type: "QUERY_LOGINS" });
  if (isErrorResponse(matches) || matches.length === 0) return;
  showDropdown(target, matches, {
    onPick: (id) => void requestFill(form, id),
    onDismiss: () => undefined,
  });
}

// Worker-initiated fills (popup button / keyboard shortcut), still scoped to
// forms actually present in this document.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "VOULT_FILL_ONE") {
    const forms = findLoginForms();
    const form = forms[0];
    if (!form) {
      sendResponse({ ok: false });
      return false;
    }
    void requestFill(form, String(msg.id)).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg?.type === "VOULT_FILL_BEST") {
    const ids = (msg.ids ?? []) as string[];
    if (ids.length === 0) return false;
    const forms = findLoginForms();
    const form = forms[0];
    if (!form) return false;
    // Shortcut semantics: exactly one candidate fills immediately; several
    // candidates open the dropdown on the username (or password) field so the
    // user — not the page — disambiguates.
    if (ids.length === 1) {
      void requestFill(form, ids[0]);
    } else {
      void (async () => {
        const matches = await send<LoginMatch[] | { error: string }>({ type: "QUERY_LOGINS" });
        if (isErrorResponse(matches)) return;
        const anchor = form.username ?? form.password;
        showDropdown(anchor, matches, {
          onPick: (id) => void requestFill(form, id),
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
