import Svg, { Defs, Mask, Path, Rect, type SvgProps } from "react-native-svg";

/**
 * The Voult wordmark — the bolt mark plus the "Voult" lettering.
 *
 * Derived from `voult_wordmark.svg` (checked in beside this file, keep it as the
 * design source). It is a component rather than a `.svg` import for the same
 * reason as `assets/images/GoogleDriveIcon.tsx`: the Metro SVG transformer fails
 * at runtime with a module-interop error, so the artwork is inlined here.
 *
 * Two things were resolved while converting, because the source file relies on
 * its Inkscape environment:
 *
 * 1. The lettering was a <text> element in the "Tomorrow" italic face, which is
 *    not shipped anywhere in the app — every renderer would substitute a
 *    different font and the lockup would drift. The glyphs are therefore
 *    outlined to paths (Tomorrow Italic, OFL), so the wordmark is font-free.
 * 2. The wedge that splits the bolt was a black shape painted on top of the
 *    white one — i.e. it only looked right on a black background. It is now a
 *    mask, so the cut is genuinely transparent on any surface.
 *
 * The viewBox is cropped to the artwork's bounds: the source page trims the
 * right-hand edge of the "t", so the declared page size is not the real extent.
 * Re-convert after editing the .svg — the nested group transforms there are not
 * identity (the drawing is scaled by 0.7671 inside the layer).
 */

export const WORDMARK_ASPECT_RATIO = 111.47 / 294.68;

const MARK_PATH =
  "M64.83 3C39.43 22.22 9.16 46.8 0.85 53.59C-0.37 54.58 -0.27 56.08 1.14 56.82C9.57 61.21 20.09 62.74 27.89 68.01C28.93 68.72 29.63 70.33 29.31 71.49C27.95 76.5 23.61 83.53 20.85 88.58C17.47 94 14.33 99.8 11.29 105.62C8.01 111.89 10.03 113.35 15.79 108.89C36.11 93.16 64.26 71.66 71.97 65.78C73.08 64.93 73.22 63.38 71.95 62.79C69.18 61.51 62.37 58.86 44.26 50.4L44.8 51.27C46.47 53.95 47 58.55 45.25 61.18C43.96 63.11 42.46 64.93 41.07 66.82C41.03 66.87 31.41 79.81 28.66 82.18C22.23 87.7 47.78 44.03 69.67 6.77C73.91 -0.45 71.7 -2.2 64.83 3Z";

const NOTCH_PATH =
  "M44.12 50.32 29.22 77.53 27.9 80.96 27.69 81.93 27.73 82.31 27.89 82.4 28.29 82.26 29.28 81.46 30.28 80.31 36.34 73.03 37.99 70.78 39.88 68.25 42.49 64.76 44.78 61.75 45.07 61.25 45.32 60.83 45.59 60.31 45.83 59.68 46.08 58.66 46.18 57.8 46.22 56.87 46.17 56.05 46.08 55.31 45.89 54.27 45.68 53.57 45.4 52.68 45.04 51.96 44.74 51.41 44.35 50.82 44.12 50.32Z";

const LETTERING_PATH =
  "M96.07 88.24 85.31 23.24H93.42L102.33 80.56H104.36L132.93 23.24H141.93L108.59 88.24ZM169.8 88.24H147.75L139.55 78.27L144.4 50.58L154.27 42.11H176.23L184.52 52.16L179.59 79.86ZM151.45 82.06H166.62L172.35 77.21L176.59 53.13L172.62 48.28H157.36L151.72 53.13L147.48 77.21ZM199.87 88.24 192.29 78.98 198.81 42.11H206.57L200.4 77.12L204.19 82.06H215.75L226.77 72.54L232.15 42.11H239.91L231.8 88.24H224.04L225.36 80.65L216.63 88.24ZM246.26 88.24 257.73 23.24H265.49L254.02 88.24ZM277.39 88.24 270.43 79.86 275.98 48.28H271.13L272.19 42.11H277.22L281.19 30.29H286.92L284.8 42.11H294.68L293.53 48.28H283.74L278.63 77.48L281.98 81.8H289.65L288.51 88.24Z";

type VoultWordmarkProps = Omit<SvgProps, "viewBox" | "width" | "height"> & {
  width?: number;
  height?: number;
  color?: string;
};

/**
 * Sizing: give it one axis, not both. `width` derives the height, `height`
 * derives the width, so the root <svg> box always matches the artwork and the
 * logo has no padding of its own. Passing both makes the box a different shape
 * from the picture, and SVG then letterboxes (or stretches) the art inside it —
 * which is exactly the "why is there so much space" symptom.
 */
export function VoultWordmark({
  width,
  height,
  color = "#FFFFFF",
  ...props
}: VoultWordmarkProps) {
  const resolvedWidth = width ?? (height ? height / WORDMARK_ASPECT_RATIO : 160);
  const resolvedHeight = height ?? resolvedWidth * WORDMARK_ASPECT_RATIO;

  return (
    <Svg
      width={resolvedWidth}
      height={resolvedHeight}
      viewBox="0 0 294.68 111.47"
      preserveAspectRatio="xMidYMid meet"
      {...props}
    >
      <Defs>
        {/* White keeps the bolt, black removes the wedge running through it. */}
        <Mask id="voult-wordmark-notch" maskUnits="userSpaceOnUse" x={0} y={0} width={294.68} height={111.47}>
          <Rect x={0} y={0} width={294.68} height={111.47} fill="#fff" />
          <Path d={NOTCH_PATH} fill="#000" />
        </Mask>
      </Defs>
      <Path d={MARK_PATH} fill={color} mask="url(#voult-wordmark-notch)" />
      <Path d={LETTERING_PATH} fill={color} />
    </Svg>
  );
}
