import {
  RecoveryPdfError,
  RECOVERY_PDF_MAX_BYTES,
  buildRecoveryPdf,
  parseRecoveryPdf,
  recoveryPdfFileName,
  type RecoveryPdfPayload,
} from "../crypto/index.web";

/**
 * The browser half of the recovery file: hand a PDF to a user, and take one
 * back.
 *
 * The format itself lives in `packages/vault-core/src/recovery-pdf.ts`, which
 * is pure and testable. Everything here is DOM plumbing that cannot be tested
 * without a browser, which is exactly why it is kept this thin — it turns a
 * `RecoveryPdfPayload` into bytes the user can keep, and bytes into a payload,
 * and does nothing else.
 *
 * Web only. The app is exported for web and served by the local server; there
 * is no native build to keep in step, so rather than pretend, every entry point
 * fails loudly if it somehow runs without a DOM.
 */

function requireDom(): void {
  if (typeof document === "undefined") {
    throw new Error("Recovery files require a browser environment.");
  }
}

/**
 * Renders the recovery payload and hands the browser a download.
 *
 * Returns the file name so the UI can tell the user exactly what to look for —
 * a silent download that lands somewhere unexpected is a recovery file the
 * user cannot find when they need it.
 *
 * Triggered only from a real click. An automatic download (fired from a mount
 * effect, with no user gesture in the same task) is silently discarded by
 * Safari, and the user would be told they had saved a file they do not have.
 */
/**
 * The artifact as a Blob.
 *
 * `new Uint8Array(bytes)` rather than passing `bytes` straight through: Blob
 * wants an ArrayBuffer-backed view, and WebCrypto's return type is only known
 * to be ArrayBufferLike. One copy of 1.4 KB is not a cost worth optimising.
 */
function pdfBlob(payload: RecoveryPdfPayload): Blob {
  return new Blob([new Uint8Array(buildRecoveryPdf(payload))], { type: "application/pdf" });
}

/**
 * Renders the recovery payload and hands the browser a download.
 *
 * Returns the file name so the UI can tell the user exactly what to look for —
 * a silent download that lands somewhere unexpected is a recovery file the
 * user cannot find when they need it.
 *
 * Triggered only from a real click. An automatic download (fired from a mount
 * effect, with no user gesture in the same task) is silently discarded by
 * Safari, and the user would be told they had saved a file they do not have.
 */
export function downloadRecoveryFile(payload: RecoveryPdfPayload): string {
  requireDom();
  const fileName = recoveryPdfFileName(payload.vaultId);
  const url = URL.createObjectURL(pdfBlob(payload));

  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = "noopener";
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  // Revoked on a long timer rather than immediately: Safari and Firefox have
  // both been seen to cancel a download whose object URL vanished in the same
  // tick as the click.
  window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
  return fileName;
}

/**
 * Prints the recovery payload, for someone who wants paper.
 *
 * Uses a hidden same-origin iframe rather than `window.open`, which popup
 * blockers refuse to let through in exactly the situation this matters — a
 * recovery attempt is often the first interaction after a long absence.
 *
 * Resolves as soon as the print dialog has been asked for; the iframe is
 * cleaned up separately, because there is no event for "the print dialog
 * closed" and tearing the document down too early cancels the print.
 */
export function printRecoveryFile(payload: RecoveryPdfPayload): void {
  requireDom();
  const url = URL.createObjectURL(pdfBlob(payload));

  const frame = document.createElement("iframe");
  frame.title = "Recovery file";
  frame.setAttribute("aria-hidden", "true");
  frame.style.position = "fixed";
  frame.style.right = "0";
  frame.style.bottom = "0";
  frame.style.width = "0";
  frame.style.height = "0";
  frame.style.border = "0";

  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    frame.remove();
    URL.revokeObjectURL(url);
  };
  // The print dialog takes focus; getting it back is the closest thing to a
  // "done" signal. The timeout is the backstop for a dialog dismissed in a way
  // that never returns focus.
  window.addEventListener("focus", cleanup, { once: true });
  window.setTimeout(cleanup, 60_000);

  frame.addEventListener("load", () => {
    try {
      frame.contentWindow?.focus();
      frame.contentWindow?.print();
    } catch (e) {
      // A blocked or unavailable print dialog must not break the flow — the
      // download button right next to it is the other half of this feature.
      console.warn("Could not open the print dialog for the recovery file", e);
      cleanup();
    }
  });

  frame.src = url;
  document.body.appendChild(frame);
}

/**
 * Opens the OS file chooser and resolves with the chosen file, or `null` if
 * the user dismissed it.
 *
 * The input is created on demand and removed immediately afterwards, so the
 * same file can be chosen twice in a row (a persistent input would not fire
 * `change` for an unchanged selection, which is the first thing a user does
 * after picking the wrong file).
 */
export function pickRecoveryFile(): Promise<File | null> {
  requireDom();

  return new Promise<File | null>((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "application/pdf,.pdf";
    input.style.display = "none";

    let settled = false;
    const finish = (file: File | null) => {
      if (settled) return;
      settled = true;
      window.removeEventListener("focus", onWindowFocus);
      input.remove();
      resolve(file);
    };
    // `cancel` is the correct signal where it exists. Where it does not, the
    // window regaining focus with no selection is the fallback — hence the
    // delay, so a file that was chosen is never lost to the race.
    const onWindowFocus = () => {
      window.setTimeout(() => finish(null), 400);
    };

    input.addEventListener("change", () => finish(input.files?.[0] ?? null), { once: true });
    if ("oncancel" in input) {
      input.addEventListener("cancel", () => finish(null), { once: true });
    } else {
      window.addEventListener("focus", onWindowFocus, { once: true });
    }

    document.body.appendChild(input);
    input.click();
  });
}

/**
 * Reads a picked or dropped file into a payload.
 *
 * The size check happens before `arrayBuffer()`: a user who drags in a video
 * should get a sentence, not a browser tab that allocates until it dies.
 *
 * MIME type is deliberately not checked. A file dragged from some file managers
 * arrives with an empty `type`, and a renamed recovery file arrives as
 * something else entirely — the parser is the real gate, and it gives a far
 * better error than a type check ever could.
 */
export async function readRecoveryFile(file: File): Promise<RecoveryPdfPayload> {
  if (file.size > RECOVERY_PDF_MAX_BYTES) {
    throw new RecoveryPdfError(
      "RECOVERY_FILE_TOO_LARGE",
      `That file is ${Math.round(file.size / 1024)} KB — too large to be a recovery file (they are about 2 KB).`,
    );
  }
  return parseRecoveryPdf(new Uint8Array(await file.arrayBuffer()));
}

/**
 * Pulls the first PDF out of a drop, if there is one.
 *
 * Returns `null` rather than throwing for the everyday misses — dropping a
 * folder, dropping nothing, dragging over a text field — so callers can stay
 * quiet about them and reserve the error slot for a file that was really
 * chosen and turned out to be wrong.
 */
export function firstPdfIn(list: FileList | null | undefined): File | null {
  if (!list) return null;
  const files = Array.from(list);
  return files.find((f) => f.type === "application/pdf" || /\.pdf$/i.test(f.name)) ?? files[0] ?? null;
}