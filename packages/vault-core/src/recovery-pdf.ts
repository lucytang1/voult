// The recovery artifact: a one-page PDF that carries a vault's recovery key.
// Two properties make this format work, and both come from owning it:
//
//   1. WE WRITE THE BYTES. No PDF library, no dependency, no font subsetting,
//      no compression. The whole document is a fixed template with a handful
//      of substitutions, so it is auditable in one sitting and its output is
//      byte-deterministic for a given payload — which is what makes it
//      testable against an independent reader (see test/recovery-pdf.test.ts,
//      which checks our writer against poppler's `pdfinfo`/`pdftotext` when
//      they are present).
//
//   2. WE READ THE BYTES. The payload is written twice — once as a visible
//      line in the content stream, once in the document Info `/Subject` — so a
//      single pass over the raw file finds it even when the page content has
//      been re-encoded. `parseRecoveryPdf` additionally inflates every stream
//      in the file, so a copy that a PDF reader re-saved (which typically
//      re-compresses and re-encodes page content) still parses.
//
// What this is NOT: it is not a general PDF text extractor, and it is not
// encrypted. The key inside is plaintext by construction — a file that could
// not be read back without another secret would not be recovery. Anyone who
// obtains the file owns the vault; that is stated on the printed page's
// companion text in the UI, and it is the same trust model as a paper copy in
// a desk drawer. What the file buys is durability and a machine-readable
// transport, not secrecy at rest.
//
// The crypto is untouched by any of this: `buildRecoveryPdf` consumes a
// recovery key that was already minted by `generateRecoverySecret`, and
// `parseRecoveryPdf` returns the same string. Nothing here is a credential
// derivation, and no server-side contract changes.

import { formatRecoveryKey, parseRecoveryKey } from "./crypto.js";
import { isValidVaultId, VAULT_ID_PATTERN } from "./origin.js";

/**
 * Format marker. Also the human/machine payload tag. Bump to `-V2` only
 * alongside a parser that still reads `-V1`, because a recovery file is the
 * last thing a stranded user has — a format change that cannot read the
 * previous version bricks recovery for every file already written to disk.
 */
export const RECOVERY_PDF_MAGIC = "VOULT-RECOVERY-V1";

/**
 * Hard input cap. A generated file is ~2 KB, so anything approaching this is
 * either the wrong file or an attempt to make the browser allocate a huge
 * buffer. Checked before `arrayBuffer()`, not after.
 */
export const RECOVERY_PDF_MAX_BYTES = 2 * 1024 * 1024;

/** Ceiling on a single inflated stream, so a crafted "PDF" cannot zip-bomb. */
const MAX_INFLATED_BYTES = 8 * 1024 * 1024;

export interface RecoveryPdfPayload {
  vaultId: string;
  /** `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` */
  recoveryKey: string;
}

export type RecoveryPdfErrorCode =
  | "RECOVERY_FILE_EMPTY"
  | "RECOVERY_FILE_TOO_LARGE"
  | "RECOVERY_FILE_NOT_PDF"
  | "RECOVERY_FILE_NO_PAYLOAD"
  | "RECOVERY_FILE_AMBIGUOUS"
  | "RECOVERY_FILE_INVALID";

/**
 * Carries a machine-readable code alongside the message so the UI can say
 * something actionable instead of "parse error". Note what is deliberately
 * absent: there is no code distinguishing "right file, wrong vault" from
 * "wrong file". That distinction is not knowable here, and the recovery
 * endpoints already answer every failure with one uniform 401 — see
 * `apps/server/src/endpoints/recovery.rs`.
 */
export class RecoveryPdfError extends Error {
  readonly code: RecoveryPdfErrorCode;

  constructor(code: RecoveryPdfErrorCode, message: string) {
    super(message);
    this.name = "RecoveryPdfError";
    this.code = code;
  }
}

// --- Writer ----------------------------------------------------------------

/** US Letter, in points. */
const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;

/**
 * Courier and Courier-Bold advance exactly 600/1000 em on every glyph, which
 * is the whole reason the page uses only these two.
 *
 * Centring a line therefore needs no font metrics at all: width is just
 * `characters x size x 0.6`. A proportional font would need a width table
 * shipped alongside it, which is real weight to carry for a document that
 * contains one sentence and one key.
 */
const MONOSPACE_EM = 0.6;

/** Page width available to a line, in points, after a 48pt margin each side. */
const MARGIN = 48;

type Line = {
  bold: boolean;
  size: number;
  /** Baseline y, in points from the bottom of the page. */
  y: number;
  text: string;
  gray?: number;
};

/** Left edge that puts a line of this width in the middle of the page. */
function centeredX(text: string, size: number): string {
  const width = text.length * size * MONOSPACE_EM;
  const available = PAGE_WIDTH - MARGIN * 2;
  // Overlong lines (only the 6pt payload line is ever near this) are pinned to
  // the margin rather than pushed off the page.
  const x = width >= available ? MARGIN : MARGIN + (available - width) / 2;
  return x.toFixed(2);
}

/**
 * Renders the recovery payload into the fixed page layout.
 *
 * Three blocks, deliberately plain: what the file is, which vault it opens,
 * and the key itself. The key is set at 24pt, on two lines of four groups,
 * because the point of the printed copy is that a human can read it aloud
 * over the phone to someone at the other end.
 */
function pageLines(payload: RecoveryPdfPayload): Line[] {
  const [first, second] = splitKeyGroups(payload.recoveryKey);
  return [
    { bold: true, size: 16, y: 700, text: "VOULT VAULT RECOVERY" },
    { bold: false, size: 10, y: 672, text: `Vault: ${payload.vaultId}` },
    { bold: true, size: 24, y: 618, text: first },
    { bold: true, size: 24, y: 584, text: second },
    // The machine-readable copy of the same payload, in the page content
    // stream. Duplicated into /Info below; either alone is enough to parse,
    // and having both means a file that survives re-encoding still reads.
    {
      bold: false,
      size: 6,
      y: 96,
      gray: 0.45,
      text: serializePayload(payload),
    },
  ];
}

/** `A-B-C-D-E-F-G-H` -> `["A-B-C-D", "E-F-G-H"]`. */
function splitKeyGroups(key: string): [string, string] {
  const groups = key.split("-");
  return [groups.slice(0, 4).join("-"), groups.slice(4).join("-")];
}

/**
 * The one line both the writer and the parser agree on. Field order and
 * separators are a wire contract inside a file format — keep the reader
 * tolerant instead of tightening this.
 */
export function serializePayload(payload: RecoveryPdfPayload): string {
  return `${RECOVERY_PDF_MAGIC} vault=${payload.vaultId} key=${payload.recoveryKey}`;
}

/** A PDF literal string. Only ASCII survives; anything else is not our input. */
function pdfString(text: string): string {
  let out = "(";
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0x3f;
    if (code < 0x20 || code > 0x7e) {
      out += "?";
    } else if (ch === "(" || ch === ")" || ch === "\\") {
      out += `\\${ch}`;
    } else {
      out += ch;
    }
  }
  return `${out})`;
}

/** `/CreationDate` as the PDF date string `D:YYYYMMDDHHmmSSZ` (always UTC). */
function pdfDate(date: Date): string {
  const pad = (n: number, width = 2) => String(n).padStart(width, "0");
  return (
    `D:${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`
  );
}

export interface BuildRecoveryPdfOptions {
  /** Defaults to now. Pinned in tests for deterministic bytes. */
  createdAt?: Date;
}

/**
 * Builds the recovery PDF.
 *
 * Deterministic: the same payload and `createdAt` always produce the same
 * bytes, which is what lets a test pin a golden file and what makes "did this
 * file change?" answerable.
 *
 * Throws `RECOVERY_FILE_INVALID` rather than emitting a document that cannot
 * be read back — a recovery file that parses to nothing is worse than no file,
 * because the user believes they are covered.
 */
export function buildRecoveryPdf(
  input: RecoveryPdfPayload,
  options: BuildRecoveryPdfOptions = {},
): Uint8Array {
  const payload = normalizePayload(input);
  const createdAt = options.createdAt ?? new Date();

  const content =
    "BT\n" +
    pageLines(payload)
      .map((line) => {
        const gray = line.gray ?? 0;
        const color = gray === 0 ? "" : `${gray} ${gray} ${gray} rg\n`;
        // One text object for the whole page; each line is positioned absolutely
        // so the layout is a property of the template, not of operator order.
        return `${color}/F${line.bold ? 2 : 1} ${line.size} Tf\n1 0 0 1 ${centeredX(line.text, line.size)} ${line.y} Tm\n${pdfString(line.text)} Tj`;
      })
      .join("\n") +
    "\nET";

  const objects: string[] = [
    // 1 — catalog
    "<< /Type /Catalog /Pages 2 0 R >>",
    // 2 — page tree
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    // 3 — the page. Standard Type1 base-14 fonts only: no embedding, no
    //     subsetting, nothing a reader has to be asked to trust.
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] ` +
      "/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> " +
      "/Contents 6 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>",
    // 6 — page content, deliberately uncompressed so the payload is greppable
    //     in the raw bytes. It is a secret either way; compression here would
    //     only make it harder to audit what we ship.
    `<< /Length ${new TextEncoder().encode(content).length} >>\nstream\n${content}\nendstream`,
    // 7 — document info, carrying the payload a second time.
    "<< /Title " +
      pdfString("Voult vault recovery") +
      " /Subject " +
      pdfString(serializePayload(payload)) +
      " /Creator " +
      pdfString("Voult") +
      " /Producer " +
      pdfString("Voult recovery file") +
      " /CreationDate " +
      pdfString(pdfDate(createdAt)) +
      " >>",
  ];

  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  let offset = 0;
  const push = (text: string) => {
    const bytes = encoder.encode(text);
    chunks.push(bytes);
    offset += bytes.length;
  };

  push("%PDF-1.4\n");
  // The conventional high-byte comment line: tells transfer agents this is a
  // binary stream, so an HTTP or mail transfer cannot mangle it as text.
  chunks.push(new Uint8Array([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]));
  offset += 6;

  const xref: number[] = [];
  objects.forEach((body, i) => {
    xref.push(offset);
    push(`${i + 1} 0 obj\n${body}\nendobj\n`);
  });

  const startxref = offset;
  let table = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const at of xref) {
    table += `${String(at).padStart(10, "0")} 00000 n \n`;
  }
  // Object numbering is positional (objects are numbered 1..N in write order),
  // so the Info dictionary — always written last — is object N.
  table +=
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R ` +
    `/Info ${objects.length} 0 R >>\nstartxref\n${startxref}\n%%EOF\n`;
  push(table);

  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/**
 * Canonicalises whatever the caller had, so the file always contains a key in
 * exactly the one accepted spelling: lowercase input, spaces, or dashes in odd
 * places are all normalised away here rather than written into the artifact.
 */
function normalizePayload(input: RecoveryPdfPayload): RecoveryPdfPayload {
  const vaultId = input.vaultId.trim().toLowerCase();
  if (!isValidVaultId(vaultId)) {
    throw new RecoveryPdfError(
      "RECOVERY_FILE_INVALID",
      `Refusing to build a recovery file for a non-UUID vault id: "${input.vaultId}"`,
    );
  }
  let recoveryKey: string;
  try {
    recoveryKey = formatRecoveryKey(parseRecoveryKey(input.recoveryKey));
  } catch {
    throw new RecoveryPdfError(
      "RECOVERY_FILE_INVALID",
      "Refusing to build a recovery file from a malformed recovery key.",
    );
  }
  return { vaultId, recoveryKey };
}

/**
 * Constant by design: a file name is the one part of this artifact that ends
 * up indexed by every backup and search tool on the machine, so no part of the
 * vault id may leak into it. A policy that embedded even 8 hex characters
 * would also need sanitising, malformed-id handling, and a boundary — all
 * for a slice a folder timestamp already provides.
 */
export function recoveryPdfFileName(_vaultId: string): string {
  // Constant by design: the file lands in backup and search indexes, so no
  // part of the vault id may appear in the name. Two copies cannot be told
  // apart by name, but they can by timestamp / containing folder.
  return "voult-recovery-kit.pdf";
}

// --- Reader ----------------------------------------------------------------

/** The anchored UUID from `origin.ts`, with its anchors stripped for matching. */
const UUID_BODY = new RegExp(VAULT_ID_PATTERN.source.slice(1, -1));

const PAYLOAD_PATTERN = new RegExp(
  `${RECOVERY_PDF_MAGIC}\\s+vault=(${UUID_BODY.source})\\s+key=([0-9A-Za-z-]{39})`,
  "g",
);

/**
 * Pulls tagged payload lines out of one decoded text source.
 *
 * We write the payload in one tagged spelling (`VOULT-RECOVERY-V1 vault=...`),
 * so a scan for that spelling is the whole extraction. Re-saved files still
 * read because we also scan inside inflated streams; anything a producer has
 * re-encoded past recognition is reported as needing the original file
 * rather than guessed at.
 */
function extractFrom(text: string): RecoveryPdfPayload[] {
  const found: RecoveryPdfPayload[] = [];
  const seen = new Set<string>();
  const push = (vaultId: string, recoveryKey: string) => {
    const id = vaultId.trim().toLowerCase();
    const key = recoveryKey.trim().toUpperCase();
    const fingerprint = `${id}|${key}`;
    if (seen.has(fingerprint)) return;
    seen.add(fingerprint);
    found.push({ vaultId: id, recoveryKey: key });
  };

  PAYLOAD_PATTERN.lastIndex = 0;
  for (const match of text.matchAll(PAYLOAD_PATTERN)) {
    push(match[1], match[2]);
  }
  return found;
}

/**
 * Reads a recovery key back out of a PDF.
 *
 * Accepts our own files and files a PDF reader has re-saved, and rejects
 * everything else. Never returns a partially-valid payload: if the file holds
 * two different keys, or a key that will not decode, that is an error the user
 * needs to see, not a coin flip.
 *
 * Async only because inflating a stream is: the raw-byte path is
 * synchronous, and a file we wrote ourselves resolves without ever touching
 * `DecompressionStream`.
 */
export async function parseRecoveryPdf(bytes: Uint8Array): Promise<RecoveryPdfPayload> {
  if (bytes.length === 0) {
    throw new RecoveryPdfError("RECOVERY_FILE_EMPTY", "That file is empty.");
  }
  if (bytes.length > RECOVERY_PDF_MAX_BYTES) {
    throw new RecoveryPdfError(
      "RECOVERY_FILE_TOO_LARGE",
      `That file is too large to be a recovery file (limit ${Math.floor(
        RECOVERY_PDF_MAX_BYTES / 1024,
      )} KB).`,
    );
  }

  const raw = toLatin1(bytes);
  if (!raw.includes("%PDF-")) {
    throw new RecoveryPdfError(
      "RECOVERY_FILE_NOT_PDF",
      "That is not a PDF. Choose the recovery file you saved, not a photo or a text file.",
    );
  }

  const sources = [raw, ...(await inflateStreams(raw))];
  const candidates: RecoveryPdfPayload[] = [];
  for (const source of sources) {
    candidates.push(...extractFrom(source));
  }

  const unique = new Map(candidates.map((c) => [`${c.vaultId}|${c.recoveryKey}`, c]));
  if (unique.size === 0) {
    throw new RecoveryPdfError(
      "RECOVERY_FILE_NO_PAYLOAD",
      "No recovery key found in that PDF. It needs to be the original file you saved — a print-out, a re-scanned page, or a copy re-saved from another PDF reader may not carry it.",
    );
  }
  if (unique.size > 1) {
    throw new RecoveryPdfError(
      "RECOVERY_FILE_AMBIGUOUS",
      "That PDF appears to contain more than one recovery key.",
    );
  }

  // Re-validate through the canonical parser: the regexes above are deliberately
  // permissive, and this is the last gate before a key is used to derive
  // anything.
  const payload = [...unique.values()][0];
  if (!isValidVaultId(payload.vaultId)) {
    throw new RecoveryPdfError("RECOVERY_FILE_INVALID", "That file has no valid vault id.");
  }
  try {
    payload.recoveryKey = formatRecoveryKey(parseRecoveryKey(payload.recoveryKey));
  } catch {
    throw new RecoveryPdfError(
      "RECOVERY_FILE_INVALID",
      "That file contains a recovery key that is not well-formed.",
    );
  }
  return payload;
}

/** Byte-per-character decoding: one byte becomes exactly one char. */
function toLatin1(bytes: Uint8Array): string {
  const CHUNK = 0x8000;
  let out = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return out;
}

/**
 * Inflates every stream in the file and returns the ones that decompress.
 *
 * Deliberately does not parse stream dictionaries. A file that survived a
 * re-save has unpredictable filters, and the cost of just *trying* every
 * stream is bounded by the input cap and `MAX_INFLATED_BYTES` — whereas
 * guessing the filter wrong means the payload is never found.
 */
async function inflateStreams(text: string): Promise<string[]> {
  if (typeof DecompressionStream === "undefined") return [];

  const out: string[] = [];
  let cursor = 0;
  while (cursor < text.length) {
    const start = text.indexOf("stream", cursor);
    if (start === -1) break;
    // Skip the keyword, then the EOL the spec requires after `stream`.
    let dataStart = start + "stream".length;
    if (text[dataStart] === "\r") dataStart += 1;
    if (text[dataStart] === "\n") dataStart += 1;
    const end = text.indexOf("endstream", dataStart);
    if (end === -1) break;
    cursor = end + "endstream".length;

    const slice = text.slice(dataStart, end);
    // The EOL before `endstream` is framing, not stream data. Readers are
    // lenient about it; `DecompressionStream` rejects the trailing junk, so
    // both forms are attempted rather than guessing which producer did what.
    for (const candidate of [slice, stripTrailingEol(slice)]) {
      for (const format of ["deflate", "deflate-raw"] as const) {
        const inflated = await inflate(candidate, format);
        if (inflated) {
          out.push(inflated);
          break;
        }
      }
    }
  }
  return out;
}

/** Drops one trailing CR/LF pair, or a single trailing CR or LF. */
function stripTrailingEol(data: string): string {
  if (data.endsWith("\r\n")) return data.slice(0, -2);
  if (data.endsWith("\n") || data.endsWith("\r")) return data.slice(0, -1);
  return data;
}

async function inflate(data: string, format: "deflate" | "deflate-raw"): Promise<string | null> {
  try {
    const bytes = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 1) bytes[i] = data.charCodeAt(i) & 0xff;

    const stream = new DecompressionStream(format);
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    // Errors surface on the reader, not here; swallow the write side so a
    // non-compressed stream does not become an unhandled rejection.
    writer.write(bytes).then(
      () => writer.close().catch(() => {}),
      () => {},
    );

    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_INFLATED_BYTES) return null;
      chunks.push(value);
    }
    if (total === 0) return null;

    const merged = new Uint8Array(total);
    let at = 0;
    for (const chunk of chunks) {
      merged.set(chunk, at);
      at += chunk.length;
    }
    return toLatin1(merged);
  } catch {
    return null;
  }
}
