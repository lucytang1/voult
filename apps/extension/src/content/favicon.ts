// Favicon discovery for the content isolate.
//
// Reads the page's own `<link rel="icon">` (resolved absolute against the
// page URL) as a fallback icon hint. Dependency-free on purpose: this module
// ships inside the single-file content IIFE, which must not gain runtime
// imports (see oauth.ts).
//
// Second choice, not first: the worker prefers the browser's own
// `sender.tab.favIconUrl` (literally the icon on the tab) and only uses this
// hint when the tab exposes none — DOM scraping can pick a different variant
// (theme/size) than the tab shows.
//
// The worker treats the result as an untrusted hint: it re-validates the URL
// (http(s) only, length-capped) and stamps nothing from page claims except
// this icon URL — origin still comes from `sender.tab.url`.

const FAVICON_MAX_LENGTH = 2048;

/** Absolute http(s) URL of the page's declared icon, or null. */
export function currentFaviconUrl(): string | null {
  try {
    const links = [...document.querySelectorAll<HTMLLinkElement>('link[rel]')];
    const candidates = links.filter((l) => /\bicon\b/i.test(l.rel) && !!l.href);
    // Prefer a raster icon with an explicit size (closest to 32px wins —
    // that is the size renderers display); then SVG; then anything declared.
    let best: string | null = null;
    let bestScore = Number.POSITIVE_INFINITY;
    for (const link of candidates) {
      // Themed variants (e.g. `media="(prefers-color-scheme: dark)"`) only
      // count when they match the user's current scheme — the tab's icon
      // does, so a non-matching variant would store a visibly different icon
      // than the tab shows.
      try {
        const media = (link.getAttribute("media") ?? "").trim();
        if (media && media.toLowerCase() !== "all" && !window.matchMedia(media).matches) {
          continue;
        }
      } catch {
        continue;
      }
      let absolute: string;
      try {
        absolute = new URL(link.getAttribute("href") ?? "", window.location.href).href;
      } catch {
        continue;
      }
      if (!/^https?:\/\//i.test(absolute) || absolute.length > FAVICON_MAX_LENGTH) continue;
      const sizes = (link.getAttribute("sizes") ?? "").toLowerCase();
      const m = /(\d+)\s*x\s*(\d+)/.exec(sizes);
      if (m) {
        const score = Math.abs(Math.max(Number(m[1]), Number(m[2])) - 32);
        if (score < bestScore) {
          bestScore = score;
          best = absolute;
        }
        continue;
      }
      const rel = link.rel.toLowerCase();
      if (best === null) {
        best = absolute;
      } else if (rel.includes("apple-touch-icon") && bestScore === Number.POSITIVE_INFINITY) {
        // Prefer the touch icon over a sizeless generic icon.
        best = absolute;
      }
    }
    return best;
  } catch {
    return null;
  }
}
