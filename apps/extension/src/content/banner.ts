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

let host: HTMLElement | null = null;
let currentCb: BannerCallbacks | null = null;

const STYLE = `
:host { all: initial; }
.voult-banner {
  position: fixed; bottom: 18px; right: 18px; z-index: 2147483647;
  width: 300px; background: #17191f; color: #e8eaf0;
  border: 1px solid #333845; border-radius: 12px;
  box-shadow: 0 8px 28px rgba(0,0,0,.5); padding: 12px;
  font: 13px/1.45 system-ui, -apple-system, sans-serif;
}
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
