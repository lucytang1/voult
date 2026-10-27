import { forwardRef, useState } from "react";
import { TextInput } from "react-native";
import type { TextInputProps } from "react-native";

/**
 * The app's text field.
 *
 * One look for every input in the product:
 *   - surface: `bg-surface2` — the flat card colour, not the purple input tint
 *   - border:  `border-hairline` at rest, `border-hairline-accent` when focused
 *   - text:    `text-primary-text` once something is typed
 *   - hint:    the placeholder in the muted-text colour
 *
 * The focused border is driven by React state rather than a CSS `:focus`
 * variant, so it behaves identically on web and on native.
 *
 * `className` is for layout only (width, margins). The colours above belong to
 * the field and are not meant to be overridden per call site.
 */
export const TextField = forwardRef<TextInput, TextInputProps>(
  ({ className = "", onFocus, onBlur, ...props }, ref) => {
    const [focused, setFocused] = useState(false);

    return (
      <TextInput
        ref={ref}
        // Muted text — the same colour the rest of the app uses for secondary
        // copy. The browser's own focus ring is suppressed in global.css so
        // the accent border is the only focus cue.
        placeholderTextColor="#7E8590"
        onFocus={(event) => {
          setFocused(true);
          onFocus?.(event);
        }}
        onBlur={(event) => {
          setFocused(false);
          onBlur?.(event);
        }}
        className={[
          "w-full rounded-lg border bg-surface2 px-4 py-3 text-primary-text",
          focused ? "border-hairline-accent" : "border-hairline",
          className,
        ]
          .filter(Boolean)
          .join(" ")}
        {...props}
      />
    );
  },
);

TextField.displayName = "TextField";
