#!/usr/bin/env node
/**
 * Release gate for the exported Expo web client.
 *
 * This is deliberately dependency-free: it runs from `apps/client`, reads only
 * `dist/`, and fails the build when the shipped artifact contains something the
 * security policy does not allow. It is not a proof of safety; `connect-src
 * 'self'` in the CSP is the runtime guarantee. This gate catches the classes of
 * mistake that a CSP cannot: source maps, accidental secrets, an unexpected
 * third-party SDK, or the debug route coming back.
 *
 * The CSP hash is derived from the actual HTML and must match `dist/_headers`.
 * If Expo changes its hydration snippet, the build fails here with the new
 * hash; update `apps/server/src/security_headers.rs` and
 * `apps/client/public/_headers`, then run `cargo test` (the Rust test pins the
 * same hash and the `_headers` parity).
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const DIST = resolve(process.cwd(), "dist");
const CLIENT_SRC = resolve(process.cwd(), "src");
const VAULT_CORE_SRC = resolve(process.cwd(), "../../packages/vault-core/src");

const INLINE_SCRIPT = "globalThis.__EXPO_ROUTER_HYDRATE__=true;";
const INLINE_HASH = `sha256-${createHash("sha256").update(INLINE_SCRIPT).digest("base64")}`;

// Hosts that are known to be inert documentation/licence strings in the
// current bundle. A new host is a review event: it may be telemetry or a
// dependency phoning home. `connect-src 'self'` blocks it at runtime either
// way, but shipping it at all is a decision that should be made explicitly.
const ALLOWED_HOSTS = new Map([
  ["www.w3.org", "SVG/XML namespace strings"],
  ["json-schema.org", "Zod schema $id strings"],
  ["reactnavigation.org", "React Navigation docs links"],
  ["github.com", "library source/licence links"],
  ["react.dev", "React docs/error links"],
  ["emscripten.org", "sqlite-wasm licence/docs strings"],
  ["sqlite.org", "sqlite-wasm licence/docs strings"],
  ["developer.chrome.com", "sqlite-wasm OPFS comment link"],
  ["tailwindcss.com", "generated CSS licence comment"],
  ["localhost", "library fallback string; not a request"],
]);

// Field names such as `vault_verifier` are part of the wire contract and are
// intentionally present in the client. Only actual secret material and
// server-only env names are forbidden.
const FORBIDDEN_STRINGS = [
  "SESSION_COOKIE_KEY",
  "GOOGLE_CLIENT_SECRET",
  "DROPBOX_CLIENT_SECRET",
  "DATABASE_URL",
  "-----BEGIN",
  "AKIA",
  "ghp_",
  "xoxb-",
  "xoxp-",
];

// Match SDK identifiers/hosts, not common words. Bare "segment" occurs many
// times in the router bundle and is not telemetry.
const TELEMETRY_MARKERS = [
  "posthog",
  "sentry",
  "amplitude",
  "mixpanel",
  "datadog",
  "bugsnag",
  "fullstory",
  "hotjar",
  "segment.io",
  "api.segment.io",
  "analytics.js",
];

const ALLOWED_ENV = new Set(["EXPO_PUBLIC_API_URL", "NODE_ENV"]);
const TEXT_EXT = new Set([
  ".html",
  ".js",
  ".mjs",
  ".css",
  ".json",
  ".txt",
  ".map",
]);
const SOURCE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs"]);

const problems = [];

function fail(message) {
  problems.push(message);
}

function isText(file) {
  return TEXT_EXT.has(file.ext);
}

function readText(file) {
  try {
    return readFileSync(file.path, "utf8");
  } catch {
    return "";
  }
}

function walk(root) {
  const out = [];
  if (!existsSync(root)) return out;
  const visit = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(full);
      } else if (entry.isFile()) {
        const rel = relative(root, full).split("\\").join("/");
        const dot = entry.name.lastIndexOf(".");
        out.push({
          path: full,
          rel,
          ext: dot >= 0 ? entry.name.slice(dot) : "",
        });
      }
    }
  };
  visit(root);
  return out;
}

function parseHeaders(raw) {
  const headers = new Map();
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("/*"))
      continue;
    const match = /^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$/.exec(trimmed);
    if (match) headers.set(match[1].toLowerCase(), match[2].trim());
  }
  return headers;
}

function parseCsp(value) {
  const directives = new Map();
  for (const part of value.split(";")) {
    const directive = part.trim();
    if (!directive) continue;
    const space = directive.indexOf(" ");
    if (space === -1) directives.set(directive, "");
    else
      directives.set(
        directive.slice(0, space),
        directive.slice(space + 1).trim(),
      );
  }
  return directives;
}

function checkCsp(headers) {
  const raw = headers.get("content-security-policy");
  if (!raw) {
    fail("dist/_headers has no Content-Security-Policy");
    return;
  }
  if (headers.has("content-security-policy-report-only")) {
    fail(
      "dist/_headers ships a report-only CSP; enforcement must not be optional",
    );
  }

  const csp = parseCsp(raw);
  const value = (name) => csp.get(name) ?? "";
  const required = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "font-src",
    "connect-src",
    "worker-src",
    "manifest-src",
    "object-src",
    "frame-src",
    "frame-ancestors",
    "base-uri",
    "form-action",
    "upgrade-insecure-requests",
  ];
  for (const name of required) {
    if (!csp.has(name)) fail(`dist/_headers CSP is missing ${name}`);
  }

  if (value("default-src") !== "'none'") fail("CSP default-src must be 'none'");
  if (!value("script-src").includes("'self'"))
    fail("CSP script-src must allow 'self'");
  if (!value("script-src").includes(INLINE_HASH)) {
    fail(
      `CSP script-src does not pin the built inline script hash ${INLINE_HASH}`,
    );
  }
  if (!value("script-src").includes("'wasm-unsafe-eval'")) {
    fail("CSP script-src must allow 'wasm-unsafe-eval' for sqlite-wasm");
  }
  if (value("script-src").includes("'unsafe-inline'")) {
    fail("CSP script-src must not contain 'unsafe-inline'");
  }
  if (value("script-src").includes("'unsafe-eval'")) {
    fail("CSP script-src must not contain 'unsafe-eval'");
  }
  if (!value("style-src").includes("'unsafe-inline'")) {
    fail(
      "CSP style-src must allow 'unsafe-inline' for React Native Web styles",
    );
  }
  if (
    !value("img-src").includes("data:") ||
    !value("img-src").includes("blob:")
  ) {
    fail("CSP img-src must allow data: and blob: for favicon/object URLs");
  }
  if (!value("img-src").includes("'self'"))
    fail("CSP img-src must allow 'self'");
  if (value("font-src") !== "'self'") fail("CSP font-src must be 'self'");
  if (value("connect-src") !== "'self'")
    fail("CSP connect-src must be exactly 'self'");
  if (
    !value("worker-src").includes("'self'") ||
    !value("worker-src").includes("blob:")
  ) {
    fail("CSP worker-src must allow 'self' and blob:");
  }
  if (value("manifest-src") !== "'self'")
    fail("CSP manifest-src must be 'self'");
  if (value("object-src") !== "'none'") fail("CSP object-src must be 'none'");
  if (value("frame-src") !== "'none'") fail("CSP frame-src must be 'none'");
  if (value("frame-ancestors") !== "'none'")
    fail("CSP frame-ancestors must be 'none'");
  if (value("base-uri") !== "'none'") fail("CSP base-uri must be 'none'");
  if (value("form-action") !== "'self'") fail("CSP form-action must be 'self'");

  const requiredHeaders = new Map([
    ["cross-origin-opener-policy", "same-origin"],
    ["cross-origin-embedder-policy", "require-corp"],
    ["x-content-type-options", "nosniff"],
    ["x-frame-options", "DENY"],
    ["referrer-policy", "no-referrer"],
  ]);
  for (const [name, expected] of requiredHeaders) {
    const actual = headers.get(name);
    if (actual !== expected)
      fail(
        `dist/_headers ${name} must be '${expected}' (got '${actual ?? "missing"}')`,
      );
  }
  if (!headers.get("permissions-policy")?.includes("clipboard-write=(self)")) {
    fail("dist/_headers Permissions-Policy must allow clipboard-write=(self)");
  }
  if (!headers.get("strict-transport-security")?.startsWith("max-age=")) {
    fail("dist/_headers must carry HSTS for the TLS static host");
  }
}

function checkInlineScripts(htmlFiles) {
  const scriptPattern = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  for (const file of htmlFiles) {
    const content = readText(file);
    let match;
    while ((match = scriptPattern.exec(content)) !== null) {
      const attrs = match[1];
      if (/\bsrc\s*=/.test(attrs)) continue;
      const body = match[2];
      if (body !== INLINE_SCRIPT) {
        fail(
          `${file.rel} has an unexpected inline script: ${JSON.stringify(body.slice(0, 80))}`,
        );
      }
    }
    if (/\son[a-z]+\s*=/i.test(content)) {
      fail(`${file.rel} contains an inline event handler (blocked by CSP)`);
    }
    if (/javascript:/i.test(content)) {
      fail(`${file.rel} contains a javascript: URL`);
    }
  }
}

function checkSecrets(files) {
  for (const file of files) {
    if (/(^|\/)\.env($|\.)/.test(file.rel))
      fail(`${file.rel} is an env file in the artifact`);
    if (/\.(pem|key|p12|mobileprovision)$/.test(file.rel)) {
      fail(`${file.rel} is a private-key/certificate artifact`);
    }
    if (
      /(^|\/)vault\.db$/.test(file.rel) ||
      /(^|\/)session\.key$/.test(file.rel)
    ) {
      fail(`${file.rel} is a server-side secret/database artifact`);
    }
    if (!isText(file)) continue;
    const content = readText(file);
    for (const marker of FORBIDDEN_STRINGS) {
      if (content.includes(marker))
        fail(`${file.rel} contains forbidden string ${marker}`);
    }
  }
}

function checkTelemetry(jsFiles) {
  const content = jsFiles.map(readText).join("\n");
  for (const marker of TELEMETRY_MARKERS) {
    // Word boundaries matter: `sentry` occurs inside `fsEntryName` in the
    // sqlite worker bundle, and `segment` occurs throughout the router.
    const pattern = new RegExp(
      `\\b${marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`,
      "i",
    );
    if (pattern.test(content))
      fail(`bundle contains telemetry marker ${marker}`);
  }
}

function checkHosts(files) {
  const urlPattern = /https?:\/\/[^\s"'`<>)]+/g;
  for (const file of files) {
    if (!isText(file)) continue;
    const content = readText(file);
    let match;
    while ((match = urlPattern.exec(content)) !== null) {
      const raw = match[0].replace(/[.,;:]+$/, "");
      let url;
      try {
        url = new URL(raw);
      } catch {
        continue; // template interpolations and other non-URL strings
      }
      const host = url.hostname.replace(/\.$/, "");
      if (!host || host.includes("${")) continue;
      if (!host.includes(".") && host !== "localhost") continue;
      if (!ALLOWED_HOSTS.has(host)) {
        fail(
          `${file.rel} references an unlisted host ${host}; review before allowing it`,
        );
      }
    }
    if (file.ext === ".css") {
      if (/url\(\s*["']?https?:/i.test(content))
        fail(`${file.rel} loads a remote CSS asset`);
      if (/@import\s+(?:url\()?["']?https?:/i.test(content)) {
        fail(`${file.rel} imports a remote stylesheet`);
      }
    }
  }
}

function checkSourceEnv() {
  const roots = [
    { root: CLIENT_SRC, label: "apps/client/src" },
    { root: VAULT_CORE_SRC, label: "packages/vault-core/src" },
  ];
  const envPattern =
    /process\.env(?:\.([A-Za-z0-9_]+)|\[\s*["']([A-Za-z0-9_]+)["']\s*\])/g;
  for (const { root, label } of roots) {
    for (const file of walk(root)) {
      if (!SOURCE_EXT.has(file.ext)) continue;
      const content = readText(file);
      let match;
      while ((match = envPattern.exec(content)) !== null) {
        const name = match[1] ?? match[2];
        if (!ALLOWED_ENV.has(name)) {
          fail(
            `${label}/${file.rel} reads process.env.${name}; only ${[...ALLOWED_ENV].join(", ")} are allowed`,
          );
        }
        if (
          name.startsWith("EXPO_PUBLIC_") &&
          /SECRET|KEY|TOKEN|PASSWORD/.test(name)
        ) {
          fail(`${label}/${file.rel} exposes ${name} through EXPO_PUBLIC_`);
        }
      }
    }
  }
}

if (!existsSync(join(DIST, "index.html"))) {
  console.error(
    "web-dist check: dist/index.html not found; run `npm run build:web` first",
  );
  process.exit(1);
}

const files = walk(DIST);
const htmlFiles = files.filter((file) => file.ext === ".html");
const jsFiles = files.filter(
  (file) => file.ext === ".js" || file.ext === ".mjs",
);
const cssFiles = files.filter((file) => file.ext === ".css");

if (!htmlFiles.some((file) => file.rel === "index.html"))
  fail("dist/index.html is missing");
if (
  files.some((file) => file.rel === "debug" || file.rel.startsWith("debug/"))
) {
  fail("dist/debug/ is present; the production debug route must be deleted");
}
for (const file of [...htmlFiles, ...jsFiles]) {
  const content = readText(file);
  if (content.includes("Debug Page"))
    fail(`${file.rel} contains the debug page marker`);
  if (content.includes("DEV_USER_ID")) fail(`${file.rel} contains DEV_USER_ID`);
}

for (const file of files) {
  if (file.rel.endsWith(".map")) fail(`${file.rel} is a source map`);
}
for (const file of files) {
  if (!isText(file)) continue;
  if (readText(file).includes("sourceMappingURL")) {
    fail(`${file.rel} contains sourceMappingURL`);
  }
}

checkInlineScripts(htmlFiles);
checkCsp(
  parseHeaders(
    readText({ path: join(DIST, "_headers"), rel: "_headers", ext: ".txt" }),
  ),
);
checkSecrets(files);
checkTelemetry(jsFiles);
checkHosts([...htmlFiles, ...jsFiles, ...cssFiles]);
checkSourceEnv();

if (problems.length > 0) {
  console.error("web-dist check failed:");
  for (const problem of problems) console.error(` - ${problem}`);
  process.exit(1);
}

console.log(
  `web-dist check: ${htmlFiles.length} HTML routes, ${jsFiles.length} JS bundle(s), ` +
    `${cssFiles.length} CSS bundle(s), ${files.length} files; ` +
    `inline hash ${INLINE_HASH}; no debug route, source maps, secrets, telemetry, or unlisted hosts.`,
);
