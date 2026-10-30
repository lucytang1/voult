// Origin handling for phishing-resistant login matching.
//
// Matching is on canonical origin (scheme + host [+ non-default port]) — never
// on `site` display text, path, query, title, or favicon. A lookalike host
// only ever matches itself.
//
// There is deliberately no subdomain/suffix fallback. A shared suffix does not
// prove a shared owner (`bank.co.uk` vs `other.co.uk`), and even a Public
// Suffix List cannot separate tenants of a platform that hosts them under its
// own registrable apex (`wordpress.com` vs `evil.wordpress.com`). Extra origins
// are linked explicitly on the item (`urls`); automatic filling is decided in
// exactly one place, `decideFillBest`.

/**
 * A vault id is a client-generated UUID (see `crypto.ts`). Exported because the
 * recovery-PDF parser has to *extract* one out of a document, not merely test
 * it — and a second copy of this pattern is a second thing to keep in sync.
 */
export const VAULT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidVaultId(vaultId: string): boolean {
  return VAULT_ID_PATTERN.test(vaultId);
}

/** Dev-loopback hosts allowed over http (plus literal loopback IPs). */
function isLoopbackHost(host: string): boolean {
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".test") ||
    host === "127.0.0.1" ||
    host === "[::1]"
  );
}

/**
 * Canonicalizes a URL/origin string to `scheme://host[:port]`.
 * Lowercases scheme+host, strips default ports and the DNS root dot, rejects
 * non-http(s) schemes (except http on loopback for dev). Throws on anything
 * unparseable.
 */
export function canonicalizeOrigin(input: string): string {
  const trimmed = input.trim();
  // Bare hosts ("example.com") are treated as https.
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  const url = new URL(withScheme);
  const scheme = url.protocol.replace(":", "").toLowerCase();
  if (scheme !== "https" && scheme !== "http") {
    throw new Error(`Unsupported scheme for origin: ${scheme}`);
  }
  // `URL.hostname` has already lowercased ASCII and punycoded IDNs. It keeps
  // the DNS root dot, so `https://example.com.` would otherwise never equal
  // `https://example.com`; strip it (and any repeated dots) before comparing.
  // An all-dot host (`https://..`) becomes empty and is rejected rather than
  // producing `https://`.
  const host = url.hostname.toLowerCase().replace(/\.+$/, "");
  if (!host) throw new Error(`Origin has empty host: ${input}`);
  if (scheme === "http" && !isLoopbackHost(host)) {
    throw new Error(`Refusing non-loopback http origin: ${input}`);
  }
  // `URL.port` is empty for the scheme's default port, so a non-empty value is
  // non-default by definition.
  const port = url.port;
  return `${scheme}://${host}${port ? `:${port}` : ""}`;
}

/** Extracts the canonical origin of a tab/page URL. Throws when not http(s). */
export function originOfUrl(pageUrl: string): string {
  return canonicalizeOrigin(pageUrl);
}

export type OriginMatchRank =
  | { kind: "exact" }
  | { kind: "linked" }
  | null;

/**
 * Ranks how an item matches a page origin. Exact canonical `origin` wins, then
 * an explicitly linked `urls` entry. Any other host — parent, child, sibling,
 * or same host on another port — is a different site and does not match.
 *
 * Do not add a suffix/subdomain fallback here. Without a public-suffix
 * boundary there is no safe way to infer shared ownership, and a PSL only
 * moves the problem (multi-tenant platforms share their registrable apex) while
 * adding a data file that goes stale between extension releases.
 */
export function rankOriginMatch(
  item: { origin?: string; urls?: string[] },
  pageOrigin: string,
): OriginMatchRank {
  let page: string;
  try {
    page = canonicalizeOrigin(pageOrigin);
  } catch {
    return null;
  }
  const norm = (s: string): string | null => {
    try {
      return canonicalizeOrigin(s);
    } catch {
      return null;
    }
  };
  if (item.origin && norm(item.origin) === page) return { kind: "exact" };
  if (item.urls?.some((u) => norm(u) === page)) return { kind: "linked" };
  return null;
}

export type FillDecision<T> =
  | { kind: "fill"; match: T }
  | { kind: "choose" }
  | { kind: "none" };

/**
 * The ONLY place allowed to choose an automatic fill. `exact` and `linked` are
 * strong; every other rank — including a rank added in the future — is weak by
 * default, so a weaker match can never become a one-keystroke fill. More than
 * one strong match is ambiguous and must go to the user.
 *
 * If a weak rank is ever added back, it may still be *shown* (and filled after
 * an explicit click), but it must never be selected automatically.
 */
export function decideFillBest<T extends { rank: string }>(
  matches: readonly T[],
): FillDecision<T> {
  const strong = matches.filter(
    (m) => m.rank === "exact" || m.rank === "linked",
  );
  if (strong.length === 1) return { kind: "fill", match: strong[0] };
  return matches.length > 0 ? { kind: "choose" } : { kind: "none" };
}
