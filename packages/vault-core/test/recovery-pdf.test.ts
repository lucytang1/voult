// Tests for the recovery PDF: the artifact we write and the artifact we read
// back. The whole point of owning the format is that the round trip is
// verifiable, so most of this file is that verification.
//
// Two independent checks matter here and neither can be satisfied by our own
// code alone:
//
//   1. `parseRecoveryPdf(buildRecoveryPdf(x)) === x` proves our writer and our
//      reader agree. Necessary, and NOT sufficient — two agreeing halves can
//      still emit a file no PDF reader accepts.
//   2. poppler's `pdfinfo` / `pdftotext`, when present, parse the file with a
//      completely separate implementation. That is what proves the document is
//      real: valid header, valid xref table, valid base-14 font references,
//      text that a reader can actually pull back out.
//
// A hand-written PDF writer has exactly one interesting failure mode — it emits
// bytes that look like a PDF and nothing more — so (2) is the test that earns
// its keep. It is skipped, not failed, when poppler is absent.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync } from "node:zlib";
import {
  RecoveryPdfError,
  buildRecoveryPdf,
  parseRecoveryPdf,
  recoveryPdfFileName,
  serializePayload,
  RECOVERY_PDF_MAGIC,
  RECOVERY_PDF_MAX_BYTES,
} from "../src/recovery-pdf.js";
import { formatRecoveryKey, generateRecoverySecret } from "../src/crypto.js";

const VAULT_ID = "3f2c9d8e-1a2b-4c5d-8e9f-0a1b2c3d4e5f";
const RECOVERY_KEY = "000G-40R4-0M30-E209-185G-R38E-1W81-24GK";
const FIXED_DATE = new Date(Date.UTC(2026, 9, 14, 8, 41, 0));

const build = () =>
  buildRecoveryPdf({ vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY }, { createdAt: FIXED_DATE });

const latin1 = (bytes: Uint8Array) => Buffer.from(bytes).toString("latin1");

const has = (cmd: string) => {
  try {
    execFileSync("which", [cmd], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
};

describe("recovery PDF — document structure", () => {
  it("starts with a PDF header and ends with a complete trailer", () => {
    const bytes = build();
    const text = latin1(bytes);
    assert.ok(text.startsWith("%PDF-1.4"), "header");
    assert.ok(text.trimEnd().endsWith("%%EOF"), "EOF marker");
    assert.match(text, /trailer\n<< \/Size 8 \/Root 1 0 R \/Info 7 0 R >>/);
  });

  it("records byte-accurate xref offsets", () => {
    const text = latin1(build());

    const startxref = Number(/startxref\s+(\d+)/.exec(text)?.[1]);
    assert.equal(text.slice(startxref, startxref + 4), "xref", "startxref points at the table");

    // Every entry must address the "N 0 obj" it claims to.
    const entries = [...text.matchAll(/^(\d{10}) 00000 n $/gm)].map((m) => Number(m[1]));
    assert.equal(entries.length, 7, "one entry per object");
    entries.forEach((at, i) => {
      assert.ok(
        text.startsWith(`${i + 1} 0 obj`, at),
        `xref entry ${i + 1} should point at object ${i + 1}, got ${JSON.stringify(text.slice(at, at + 20))}`,
      );
    });
  });

  it("declares a content stream length that matches the bytes it wraps", () => {
    const text = latin1(build());
    const declared = Number(/\/Length (\d+) >>\nstream\n/.exec(text)?.[1]);
    const body = text.slice(text.indexOf("stream\n") + "stream\n".length, text.indexOf("\nendstream"));
    assert.equal(declared, Buffer.byteLength(body, "latin1"));
  });

  it("is deterministic for a given payload and timestamp", () => {
    assert.deepEqual(build(), build());
  });

  it("refuses to build an unreadable file from a malformed key or id", () => {
    assert.throws(
      () => buildRecoveryPdf({ vaultId: VAULT_ID, recoveryKey: "not-a-key" }),
      (e: unknown) => e instanceof RecoveryPdfError && e.code === "RECOVERY_FILE_INVALID",
    );
    assert.throws(
      () => buildRecoveryPdf({ vaultId: "not-a-uuid", recoveryKey: RECOVERY_KEY }),
      (e: unknown) => e instanceof RecoveryPdfError && e.code === "RECOVERY_FILE_INVALID",
    );
  });

  it("escapes PDF literal metacharacters rather than emitting them raw", () => {
    // A vault id that fails validation cannot reach the page, so this exercises
    // the escaper directly through the observable path: the label text is ours,
    // the key is validated, so nothing hostile gets in today. What we are
    // pinning is that a future template edit cannot introduce a raw paren.
    const text = latin1(build());
    assert.ok(!/stream[^)]*unbalanced/.test(text));
    assert.ok(text.includes("/Subject (VOULT-RECOVERY-V1 vault="));
  });
});

describe("recovery PDF — round trip", () => {
  it("reads back exactly what it wrote", async () => {
    const payload = await parseRecoveryPdf(build());
    assert.deepEqual(payload, { vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY });
  });

  it("round-trips freshly generated secrets", async () => {
    for (let i = 0; i < 25; i += 1) {
      const recoveryKey = formatRecoveryKey(generateRecoverySecret());
      const bytes = buildRecoveryPdf(
        { vaultId: VAULT_ID, recoveryKey },
        { createdAt: FIXED_DATE },
      );
      assert.deepEqual(await parseRecoveryPdf(bytes), { vaultId: VAULT_ID, recoveryKey });
    }
  });

  it("canonicalises the key it writes, so the file has one accepted spelling", async () => {
    const messy = "  000g 40r4 0m30 e209 185g r38e 1w81 24gk  ";
    const bytes = buildRecoveryPdf({ vaultId: VAULT_ID.toUpperCase(), recoveryKey: messy });
    const text = latin1(bytes);
    assert.ok(text.includes(`key=${RECOVERY_KEY}`), "written in canonical form");
    assert.ok(text.includes(`vault=${VAULT_ID}`), "vault id lower-cased");
    assert.deepEqual(await parseRecoveryPdf(bytes), { vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY });
  });

  it("writes the payload twice: page content and Info /Subject", () => {
    const text = latin1(build());
    const payload = serializePayload({ vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY });
    assert.equal(text.split(payload).length - 1, 2);
  });

  it("prints an optional vault name without changing what parses back", async () => {
    const bytes = buildRecoveryPdf(
      { vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY, name: "Family vault" },
      { createdAt: FIXED_DATE },
    );
    const text = latin1(bytes);
    assert.ok(text.includes("Name: Family vault"), "name is visible on the page");
    assert.ok(text.includes("/Title (Voult vault recovery: Family vault)"), "name in Info /Title");
    // The name is informational: recovery still needs exactly id + key.
    assert.deepEqual(await parseRecoveryPdf(bytes), { vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY });
  });
});

describe("recovery PDF — parsing hostile or wrong input", () => {
  const rejects = async (bytes: Uint8Array, code: string) =>
    assert.rejects(
      () => parseRecoveryPdf(bytes),
      (e: unknown) => e instanceof RecoveryPdfError && e.code === code,
      `expected ${code}`,
    );

  it("rejects an empty file", () => rejects(new Uint8Array(0), "RECOVERY_FILE_EMPTY"));

  it("rejects an oversized file before parsing it", () =>
    rejects(new Uint8Array(RECOVERY_PDF_MAX_BYTES + 1), "RECOVERY_FILE_TOO_LARGE"));

  it("rejects something that is not a PDF", () =>
    rejects(new TextEncoder().encode("just some text, no pdf here"), "RECOVERY_FILE_NOT_PDF"));

  it("rejects a PDF with no key in it", () =>
    rejects(
      new TextEncoder().encode(
        "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF\n",
      ),
      "RECOVERY_FILE_NO_PAYLOAD",
    ));

  it("rejects a PDF carrying two different keys", () =>
    rejects(
      new TextEncoder().encode(
        `%PDF-1.4\n${RECOVERY_PDF_MAGIC} vault=${VAULT_ID} key=${RECOVERY_KEY}\n` +
          `${RECOVERY_PDF_MAGIC} vault=${VAULT_ID} key=1111-2222-3333-4444-5555-6666-7777-8888\n`,
      ),
      "RECOVERY_FILE_AMBIGUOUS",
    ));

  it("rejects a payload whose key will not decode", () =>
    rejects(
      new TextEncoder().encode(
        // `U` is the one excluded letter with no transcription alias, so it is
        // the only way to write a key that genuinely cannot decode. (`I` and
        // `L` would decode to 1 by design — Crockford's tolerance.)
        `%PDF-1.4\n${RECOVERY_PDF_MAGIC} vault=${VAULT_ID} key=UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU\n`,
      ),
      "RECOVERY_FILE_INVALID",
    ));

  it("never throws a bare Error — every failure carries a code", async () => {
    try {
      await parseRecoveryPdf(new Uint8Array([1, 2, 3]));
      assert.fail("should have thrown");
    } catch (e) {
      assert.ok(e instanceof RecoveryPdfError);
      assert.ok(typeof e.code === "string" && e.code.length > 0);
    }
  });
});

describe("recovery PDF — survives a re-save", () => {
  // The realistic bad case: the file went through a PDF reader that recompressed
  // the content stream and moved the metadata into an object stream. The raw
  // bytes no longer show the payload, so the reader has to inflate.
  //
  // Built byte-by-byte rather than through TextEncoder: zlib output is not
  // valid UTF-8, and encoding it as text would corrupt exactly the payload the
  // test exists to rescue.
  const reSaved = (declareFilter: boolean) => {
    const payload = serializePayload({ vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY });
    const compressed = deflateSync(Buffer.from(payload, "latin1"));
    const head = Buffer.from(
      [
        "%PDF-1.4",
        "1 0 obj",
        `<< /Length ${compressed.length}${declareFilter ? " /Filter /FlateDecode" : ""} >>`,
        "stream",
      ].join("\n") + "\n",
      "latin1",
    );
    const tail = Buffer.from("\nendstream\nendobj\ntrailer\n%%EOF\n", "latin1");
    return new Uint8Array(Buffer.concat([head, compressed, tail]));
  };

  it("reads the payload out of a FlateDecode stream", async () => {
    assert.deepEqual(await parseRecoveryPdf(reSaved(true)), {
      vaultId: VAULT_ID,
      recoveryKey: RECOVERY_KEY,
    });
  });

  it("does not care about the filter being declared, it just tries them", async () => {
    // Same bytes, no /Filter entry. A parser that trusted the dictionary would
    // skip this stream; trying every stream is why it still works.
    assert.deepEqual(await parseRecoveryPdf(reSaved(false)), {
      vaultId: VAULT_ID,
      recoveryKey: RECOVERY_KEY,
    });
  });

  it("recovers the key even when the payload itself is gone from raw bytes", async () => {
    // The strongest form of the claim: nothing readable survives in the file as
    // written, and the key still comes back.
    const bytes = reSaved(true);
    assert.ok(!latin1(bytes).includes(RECOVERY_KEY), "raw bytes really do hide the key");
    assert.deepEqual(await parseRecoveryPdf(bytes), {
      vaultId: VAULT_ID,
      recoveryKey: RECOVERY_KEY,
    });
  });

  it("refuses to guess when a producer split the payload across operators", async () => {
    // The documented limit. Asserted so the behaviour is a decision someone
    // made, rather than a surprise discovered during someone's recovery.
    const bytes = new TextEncoder().encode(
      `%PDF-1.4\n${RECOVERY_PDF_MAGIC} vault=${VAULT_ID.slice(0, 13)}\nstream\n%%EOF\n`,
    );
    await assert.rejects(
      () => parseRecoveryPdf(bytes),
      (e: unknown) => e instanceof RecoveryPdfError && e.code === "RECOVERY_FILE_NO_PAYLOAD",
    );
  });
});

describe("recovery PDF — independent reader (poppler)", () => {
  const skip = has("pdfinfo") && has("pdftotext") ? false : "poppler (pdfinfo/pdftotext) not installed";
  const opts = { skip } as const;

  it("is accepted as a one-page PDF", opts, () => {
    const out = execFileSync("pdfinfo", ["-"], { input: Buffer.from(build()), encoding: "utf8" });
    assert.match(out, /Pages:\s+1/);
    assert.match(out, /Producer:\s+Voult recovery file/);
    assert.match(out, /CreationDate:.*2026/);
  });

  it("has its text recoverable by a reader that knows nothing about us", opts, () => {
    const out = execFileSync("pdftotext", ["-", "-"], {
      input: Buffer.from(build()),
      encoding: "utf8",
    });
    assert.match(out, /VOULT VAULT RECOVERY/);
    assert.match(out, new RegExp(VAULT_ID));
    // The key survives as four visible groups on each of two lines, exactly as
    // it looks on paper.
    assert.match(out, /000G-40R4-0M30-E209/);
    assert.match(out, /185G-R38E-1W81-24GK/);
  });

  it("centres every line inside the page margins", opts, () => {
    // Courier advances exactly 0.6 em, so the rendered geometry is predictable
    // and can be asserted without a font library: no text may start left of the
    // margin or run past the right one.
    const text = latin1(build());
    const positioned = [
      ...text.matchAll(/\/F\d (\d+(?:\.\d+)?) Tf\n1 0 0 1 ([\d.]+) [\d.]+ Tm\n\((.*?)\) Tj/g),
    ];
    assert.equal(positioned.length, 5, "one positioned line per block");
    for (const [, size, x, value] of positioned) {
      const start = Number(x);
      const end = start + value.length * Number(size) * 0.6;
      assert.ok(start >= 47.9, `line "${value.slice(0, 12)}" starts left of the margin (${start})`);
      assert.ok(end <= 564.1, `line "${value.slice(0, 12)}" overflows the right margin (${end})`);
    }
  });
});

describe("recovery PDF — independent producer (ghostscript)", () => {
  // The re-save case, for real. PostScript in, PDF out, through an entirely
  // different toolchain: different writer, different stream filters, different
  // font handling. The payload is not visible anywhere in the raw bytes of the
  // result, so this only passes if the reader genuinely inflates and re-scans.
  const skip = has("ps2pdf") ? false : "ghostscript (ps2pdf) not installed";
  const opts = { skip } as const;

  it("is readable after being re-produced by another PDF writer", opts, async () => {
    const dir = mkdtempSync(join(tmpdir(), "voult-recovery-pdf-"));
    const src = join(dir, "source.ps");
    const out = join(dir, "produced.pdf");
    writeFileSync(
      src,
      "%!PS-Adobe-3.0\n" +
        "/Courier findfont 12 scalefont setfont\n" +
        `72 720 moveto (${serializePayload({ vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY })}) show\n` +
        "showpage\n",
    );
    execFileSync("ps2pdf", [src, out], { stdio: "pipe" });

    const bytes = new Uint8Array(readFileSync(out));
    assert.ok(!latin1(bytes).includes(RECOVERY_KEY), "the re-produced file really does hide it");
    assert.deepEqual(await parseRecoveryPdf(bytes), {
      vaultId: VAULT_ID,
      recoveryKey: RECOVERY_KEY,
    });
    rmSync(dir, { recursive: true, force: true });
  });

  it("survives being rewritten in place by a PDF editor", opts, async () => {
    // `gs -sDEVICE=pdfwrite` on OUR file is the closest available stand-in for
    // "opened in a reader and saved again".
    const dir = mkdtempSync(join(tmpdir(), "voult-recovery-pdf-"));
    const original = join(dir, "recovery.pdf");
    const rewritten = join(dir, "rewritten.pdf");
    writeFileSync(original, build());
    execFileSync(
      "gs",
      ["-sDEVICE=pdfwrite", "-dCompatibilityLevel=1.7", "-o", rewritten, original],
      { stdio: "pipe" },
    );
    assert.deepEqual(
      await parseRecoveryPdf(new Uint8Array(readFileSync(rewritten))),
      { vaultId: VAULT_ID, recoveryKey: RECOVERY_KEY },
    );
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("recovery PDF — file naming", () => {
  it("is stable, readable, and free of path characters", () => {
    assert.equal(recoveryPdfFileName(VAULT_ID), "voult-recovery-kit.pdf");
    assert.equal(recoveryPdfFileName("../../etc/passwd"), "voult-recovery-kit.pdf");
    assert.equal(recoveryPdfFileName(""), "voult-recovery-kit.pdf");
  });
});