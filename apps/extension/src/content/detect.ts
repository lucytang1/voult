// Login-form discovery for the content isolate.
//
// Heuristic order (first hit wins per form):
//  1. autocomplete attributes (current-password / username / email)
//  2. input types (password + text/email peer in the same form)
//  3. nearest preceding visible text input (orphan fields, no <form>)
// Only the top frame is scanned (content.ts returns early otherwise), and
// only visible, enabled fields qualify — hidden/off-screen inputs are a
// credential-harvesting pattern and are never filled.

export interface LoginForm {
  /** Stable key for this form within the page (dedupe + banner scoping). */
  key: string;
  password: HTMLInputElement;
  username: HTMLInputElement | null;
}

function isVisible(el: HTMLElement): boolean {
  if (el.hidden) return false;
  if (el instanceof HTMLInputElement && el.disabled) return false;
  const rect = el.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return false;
  const style = window.getComputedStyle(el);
  return style.visibility !== "hidden" && style.display !== "none";
}

function visibleInputs(root: ParentNode, selector: string): HTMLInputElement[] {
  return [...root.querySelectorAll<HTMLInputElement>(selector)].filter(
    (el) => el instanceof HTMLInputElement && isVisible(el),
  );
}

function usernamePeer(password: HTMLInputElement): HTMLInputElement | null {
  const form = password.form;
  const scope: ParentNode = form ?? document;
  // 1. Explicit autocomplete hints.
  const hinted = visibleInputs(
    scope,
    'input[autocomplete="username"], input[autocomplete="email"]',
  );
  if (hinted[0]) return hinted[0];
  // 2. Typed peers in the same scope.
  const typed = visibleInputs(scope, 'input[type="text"], input[type="email"]');
  if (form && typed[0]) return typed[0];
  // 3. Nearest preceding visible text input (covers orphan fields).
  const all = visibleInputs(document, 'input[type="text"], input[type="email"]');
  const prev = all.filter((el) => el.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_PRECEDING);
  if (prev.length) return prev[prev.length - 1];
  if (!form && typed[0]) return typed[0];
  return null;
}

/** All qualifying login forms currently in the top-frame document. */
export function findLoginForms(): LoginForm[] {
  const passwords = visibleInputs(document, 'input[type="password"]');
  return passwords.map((password, i) => {
    const form = password.form;
    const key = form?.action
      ? `form:${form.action}:${i}`
      : `orphan:${fieldPath(password)}`;
    return { key, password, username: usernamePeer(password) };
  });
}

function fieldPath(el: HTMLElement): string {
  const parts: string[] = [];
  let cur: HTMLElement | null = el;
  for (let depth = 0; depth < 4 && cur; depth++) {
    const siblings = cur.parentElement ? [...cur.parentElement.children] : [];
    parts.unshift(`${cur.tagName}[${siblings.indexOf(cur)}]`);
    cur = cur.parentElement;
  }
  return parts.join(">");
}
