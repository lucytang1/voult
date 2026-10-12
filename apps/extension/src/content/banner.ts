// Page-anchored save/update banner for the content isolate.
//
// Closed ShadowRoot, textContent-only rendering (same isolation rules as the
// suggest dropdown). Dismiss is the default outcome: the banner never
// auto-saves, and ignoring it changes nothing.

export interface BannerCallbacks {
  onConfirm: () => void;
  onNever: () => void;
  onDismiss: () => void;
}

/**
 * OAuth variant: `onConfirm` receives the account the user picked from the
 * vault's known accounts for that provider, or "" when the vault knows none and
 * the sign-in is stored provider-only.
 */
export interface OAuthBannerCallbacks {
  onConfirm: (account: string) => void;
  onNever: () => void;
  onDismiss: () => void;
}

let host: HTMLElement | null = null;
let currentCb: BannerCallbacks | null = null;

const STYLE = `
:host { all: initial; }
.voult-banner {
  position: fixed; top: 18px; right: 18px; z-index: 2147483647;
  width: 300px; background: #17191f; color: #e8eaf0;
  border: 1px solid #333845; border-radius: 12px;
  box-shadow: 0 8px 28px rgba(0,0,0,.5); padding: 12px;
  font: 13px/1.45 system-ui, -apple-system, sans-serif;
}
/* Account pickers need room for a real email address per row. */
.voult-banner.wide { width: 340px; }
.voult-title { font-weight: 700; margin-bottom: 2px; }
.voult-sub { color: #9aa0ae; font-size: 12px; margin-bottom: 10px; }
.voult-actions { display: flex; gap: 6px; }
.voult-primary {
  flex: 1; background: #4f7cff; color: #fff; border: 0; border-radius: 8px;
  padding: 7px 0; font-size: 13px; font-weight: 600; cursor: pointer;
}
.voult-ghost {
  background: none; border: 0; color: #9aa0ae; font-size: 12px; cursor: pointer;
  padding: 7px 4px;
}
.voult-accounts {
  display: flex; flex-direction: column; gap: 4px; margin-bottom: 8px;
  max-height: 220px; overflow-y: auto;
}
.voult-account {
  display: block; width: 100%; text-align: left; cursor: pointer;
  background: #101216; color: #e8eaf0; border: 1px solid #333845;
  border-radius: 8px; padding: 7px 9px; font: 13px system-ui, -apple-system, sans-serif;
}
.voult-account:hover { border-color: #4f7cff; }
.voult-label { color: #9aa0ae; font-size: 12px; margin: 0 0 4px; }
.voult-hint { color: #6b7280; font-size: 11px; margin: 0 0 8px; }
`;

function teardown(): void {
  host?.remove();
  host = null;
  currentCb = null;
}

/**
 * Shows the save/update decision banner. Only one banner at a time; showing
 * a new one replaces the old. The password is never displayed.
 */
export function showSaveBanner(
  mode: "save" | "update",
  origin: string,
  username: string,
  cb: BannerCallbacks,
): void {
  teardown();
  currentCb = cb;

  host = document.createElement("div");
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = STYLE;
  shadow.appendChild(style);

  const box = document.createElement("div");
  box.className = "voult-banner";
  const title = document.createElement("div");
  title.className = "voult-title";
  title.textContent = mode === "save" ? "Save login in Voult?" : "Update saved login?";
  const sub = document.createElement("div");
  sub.className = "voult-sub";
  sub.textContent = `${username} · ${origin}`;
  const actions = document.createElement("div");
  actions.className = "voult-actions";

  const confirm = document.createElement("button");
  confirm.className = "voult-primary";
  confirm.textContent = mode === "save" ? "Save" : "Update";
  confirm.addEventListener("click", () => {
    const fns = currentCb;
    teardown();
    fns?.onConfirm();
  });

  const never = document.createElement("button");
  never.className = "voult-ghost";
  never.textContent = "Never for this site";
  never.addEventListener("click", () => {
    const fns = currentCb;
    teardown();
    fns?.onNever();
  });

  const dismiss = document.createElement("button");
  dismiss.className = "voult-ghost";
  dismiss.textContent = "Dismiss";
  dismiss.addEventListener("click", () => {
    const fns = currentCb;
    teardown();
    fns?.onDismiss();
  });

  actions.appendChild(confirm);
  actions.appendChild(never);
  actions.appendChild(dismiss);
  box.appendChild(title);
  box.appendChild(sub);
  box.appendChild(actions);
  shadow.appendChild(box);
  document.documentElement.appendChild(host);
}

export function dismissSaveBanner(): void {
  teardown();
}

/**
 * OAuth variant: "Signed in with Google?" — no secret exists to display, and we
 * cannot observe the IdP's assertion, so we never assert an account either.
 * Instead the banner offers the accounts this vault already knows for that
 * provider and the user picks one; with none known, the sign-in is stored
 * provider-only ("Sign in with Google") via a plain Save.
 *
 * Same one-banner-at-a-time and dismiss-default semantics as the password
 * banner; dismissing stores nothing.
 */
export function showOAuthSaveBanner(
  providerLabel: string,
  origin: string,
  accounts: string[],
  cb: OAuthBannerCallbacks,
): void {
  teardown();
  // Local ref rather than the shared `currentCb` slot: the OAuth callback
  // takes an argument, so it can't share that slot's narrower type.
  let cbRef: OAuthBannerCallbacks | null = cb;

  // Resolve once: whichever way this banner is answered, the decision is sent
  // and the banner goes away.
  const decide = (run: (fns: OAuthBannerCallbacks) => void) => {
    const fns = cbRef;
    teardown();
    cbRef = null;
    if (fns) run(fns);
  };

  host = document.createElement("div");
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = STYLE;
  shadow.appendChild(style);

  const box = document.createElement("div");
  box.className = accounts.length > 0 ? "voult-banner wide" : "voult-banner";
  const title = document.createElement("div");
  title.className = "voult-title";
  title.textContent = `Signed in with ${providerLabel}?`;
  const sub = document.createElement("div");
  sub.className = "voult-sub";
  sub.textContent = origin;

  const hint = document.createElement("div");
  hint.className = "voult-hint";

  const actions = document.createElement("div");
  actions.className = "voult-actions";

  const never = document.createElement("button");
  never.className = "voult-ghost";
  never.textContent = "Never for this site";
  never.addEventListener("click", () => decide((fns) => fns.onNever()));

  const dismiss = document.createElement("button");
  dismiss.className = "voult-ghost";
  dismiss.textContent = "Dismiss";
  dismiss.addEventListener("click", () => decide((fns) => fns.onDismiss()));

  box.appendChild(title);
  box.appendChild(sub);

  if (accounts.length > 0) {
    // A picker, not a free-text field: the accounts are ones this vault already
    // stores, so every option is a real identity the user can recognise.
    const label = document.createElement("div");
    label.className = "voult-label";
    label.textContent = `Which ${providerLabel} account?`;
    const list = document.createElement("div");
    list.className = "voult-accounts";
    for (const account of accounts) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "voult-account";
      row.textContent = account;
      row.addEventListener("click", () => decide((fns) => fns.onConfirm(account)));
      list.appendChild(row);
    }
    hint.textContent = "Only accounts already in your vault are listed.";
    actions.appendChild(never);
    actions.appendChild(dismiss);
    box.appendChild(label);
    box.appendChild(list);
    box.appendChild(hint);
  } else {
    // Nothing known for this provider: the honest save is the method itself.
    const confirm = document.createElement("button");
    confirm.className = "voult-primary";
    confirm.textContent = `Save "Sign in with ${providerLabel}"`;
    confirm.addEventListener("click", () => decide((fns) => fns.onConfirm("")));
    hint.textContent = "No matching account in your vault yet — this saves the sign-in method only.";
    actions.appendChild(confirm);
    actions.appendChild(never);
    actions.appendChild(dismiss);
    box.appendChild(hint);
  }

  box.appendChild(actions);
  shadow.appendChild(box);
  document.documentElement.appendChild(host);
}
