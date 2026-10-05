// Trusted fill routines for the content isolate.
//
// Values are set through the native input prototype setter (not direct
// assignment) so React/Angular/Vue controlled inputs pick up the change, then
// bubbled input/change events are dispatched. Callers must only invoke these
// on an explicit user gesture (dropdown click, shortcut, popup button).

function setInputValue(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (setter) {
    setter.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/** Fill one login form. Never auto-submits — the user presses submit. */
export function fillForm(
  form: { password: HTMLInputElement; username: HTMLInputElement | null },
  creds: { username: string; password: string },
): void {
  if (form.username) setInputValue(form.username, creds.username);
  setInputValue(form.password, creds.password);
  // Focus the password field so the user's next keystroke/submit flows
  // naturally and password managers' “did fill” heuristics stay quiet.
  form.password.focus();
}
