import { Text, View } from "react-native";

/**
 * The startup screen: the only thing that renders until `RootLayout`'s
 * bootstrap has decided where the user belongs.
 *
 * Why it exists: the store starts at `no_vault`, so rendering the router
 * immediately paints `/` (the landing) on every reload — even for a user with a
 * selected, locked or device-unlockable vault — and then redirects. That flash
 * is not just ugly; it is a lie about where the user is. Holding the routes
 * behind a splash until the decision is committed makes the first painted
 * screen the correct one.
 *
 * It is also the *prerendered* screen. `web.output: "static"` snapshots each
 * route at build time with this component gating the tree, so `dist/*.html`
 * contains the splash instead of a route's markup — the browser therefore
 * cannot paint the landing before the JS bundle has even run.
 *
 * Deliberately dumb: no state, no effects, no timers. It must render
 * identically on the server and on the client or hydration would mismatch.
 */
export function BootSplash() {
  return (
    <View className="flex-1 items-center justify-center bg-ground">
      <Text className="text-[44px] font-normal leading-[48px] tracking-[-0.02em] text-primary-text">
        Voult
      </Text>
    </View>
  );
}
