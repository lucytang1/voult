import { useEffect, useState } from "react";
import { Earth } from "lucide-react";
import { faviconForItem, type VaultItem } from "@voult/vault-core";

/**
 * Site icon: the stored favicon (else `<origin>/favicon.ico`) over an earth
 * glyph. The glyph is always rendered underneath, so a transparent or
 * still-loading icon still reads as the item instead of a blank square — and
 * an item with no icon at all still reads as a site, not as a hole.
 * `faviconForItem` only ever returns http(s) URLs, and the popup never sends a
 * referrer to the icon host.
 */
export function ItemIcon({
  item,
  plain = false,
}: {
  item: VaultItem;
  plain?: boolean;
}) {
  const [failed, setFailed] = useState(false);
  const src = faviconForItem(item);

  // A row can be reused for a different item (filter reordering can preserve a
  // component instance) — retry its icon.
  useEffect(() => setFailed(false), [src]);

  return (
    <span className={`icon-tile${plain ? " icon-tile--plain" : ""}`} aria-hidden="true">
      <Earth className="icon-tile__fallback" />
      {src && !failed && (
        <img
          src={src}
          alt=""
          width={20}
          height={20}
          onError={() => setFailed(true)}
          referrerPolicy="no-referrer"
        />
      )}
    </span>
  );
}
