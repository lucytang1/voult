// Origin handling for phishing-resistant login matching.
//
// Matching is on canonical origin (scheme + host [+ non-default port]) — never
// on `site` display text, path, query, title, or favicon. A lookalike host
// only ever matches itself.

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidVaultId(vaultId: string): boolean {
  return UUID_PATTERN.test(vaultId);
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
 * Lowercases scheme+host, strips default ports, rejects non-http(s) schemes
 * (except http on loopback for dev). Throws on anything unparseable.
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
  const host = url.hostname.toLowerCase();
  if (!host) throw new Error(`Origin has empty host: ${input}`);
  if (scheme === "http" && !isLoopbackHost(host)) {
    throw new Error(`Refusing non-loopback http origin: ${input}`);
  }
  const port = url.port;
  const isDefaultPort =
    (scheme === "https" && (port === "" || port === "443")) ||
    (scheme === "http" && (port === "" || port === "80"));
  return `${scheme}://${host}${isDefaultPort ? "" : `:${port}`}`;
}

/** Extracts the canonical origin of a tab/page URL. Throws when not http(s). */
export function originOfUrl(pageUrl: string): string {
  return canonicalizeOrigin(pageUrl);
}

export type OriginMatchRank =
  | { kind: "exact" }
  | { kind: "linked" }
  | { kind: "subdomain" }
  | null;

/**
 * Ranks how an item matches a page origin. Exact `origin` wins, then an
 * explicitly linked `urls` entry, then a same-eTLD+1 subdomain fallback
 * (caller should visually mark subdomain matches as weaker).
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
  // Subdomain fallback: same scheme + registrable suffix match. Deliberately
  // naive (last-two-labels) — marks weaker, never outranks exact/linked.
  const itemOrigin = item.origin ? norm(item.origin) : null;
  if (itemOrigin) {
    try {
      const itemUrl = new URL(itemOrigin);
      const pageUrl = new URL(page);
      if (itemUrl.protocol === pageUrl.protocol) {
        const suffix = (h: string) => h.split(".").slice(-2).join(".");
        if (suffix(itemUrl.hostname) === suffix(pageUrl.hostname)) {
          return { kind: "subdomain" };
        }
      }
    } catch {
      return null;
    }
  }
  return null;
}
