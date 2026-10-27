import type { CloudProviderInfo } from "./api";
import { GoogleDriveIcon } from "../../../assets/images/GoogleDriveIcon";
import { Cloud } from "lucide-react";
import React from "react";
import Svg, { Path, type SvgProps } from "react-native-svg";

function DropboxIcon(props: SvgProps) {
  return React.createElement(
    Svg,
    { viewBox: "0 0 24 24", width: 28, height: 28, ...props },
    React.createElement(Path, {
      fill: "#0061ff",
      d: "m7.1 2 4.9 3.2L7.1 8.4 2.2 5.2 7.1 2Zm9.8 0 4.9 3.2-4.9 3.2L12 5.2 16.9 2ZM2.2 11.6l4.9-3.2 4.9 3.2-4.9 3.2-4.9-3.2Zm14.7-3.2 4.9 3.2-4.9 3.2-4.9-3.2 4.9-3.2ZM7.1 16.5l4.9-3.2 4.9 3.2-4.9 3.2-4.9-3.2Z",
    }),
  );
}

/** UI metadata for compiled providers. The server capability response remains authoritative. */
export const cloudProviderRegistry: Record<
  string,
  { label: string; icon: typeof GoogleDriveIcon | typeof DropboxIcon }
> = {
  google_drive: { label: "Google Drive", icon: GoogleDriveIcon },
  dropbox: { label: "Dropbox", icon: DropboxIcon },
};

export const CloudProviderFallbackIcon = Cloud;

export function providerLabel(provider: CloudProviderInfo): string {
  return cloudProviderRegistry[provider.kind]?.label ?? provider.display_name;
}

export function providerLabelForKind(kind: string): string {
  return cloudProviderRegistry[kind]?.label ?? "cloud provider";
}
