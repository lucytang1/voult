import { useEffect, useState } from "react";
import { Pressable, Text, View } from "react-native";
import { useStartExtensionPairing } from "@/src/lib/queries/pair/query";

/**
 * "Connect browser extension" card for Settings → Integrations.
 * Mints a one-time pairing code (vault identity only — the extension still
 * requires the master password). Minting replaces any previous code, so the
 * newest display is the only valid one. Countdown is informational; the
 * server enforces the real TTL.
 */
export function ExtensionPairing() {
  const [code, setCode] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [error, setError] = useState<string | null>(null);
  const pairing = useStartExtensionPairing();

  useEffect(() => {
    if (!code || !expiresAt) return;
    if (now >= expiresAt) return;
    const t = setTimeout(() => setNow(Date.now()), 1000);
    return () => clearTimeout(t);
  }, [code, expiresAt, now]);

  const remaining = expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : 0;
  const expired = !!code && !!expiresAt && now >= expiresAt;

  const handleGenerate = async () => {
    setError(null);
    try {
      const res = await pairing.mutateAsync();
      setCode(res.code);
      setExpiresAt(new Date(res.expires_at).getTime());
      setNow(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate code");
    } finally {
      pairing.reset();
    }
  };

  return (
    <View className="rounded-2xl bg-surface1 overflow-hidden p-5">
      <Text className="text-primary-text text-sm font-semibold mb-1">Browser extension</Text>
      <Text className="text-muted-text text-sm mb-4">
        Pair your browser extension with this vault using a one-time code.
      </Text>
      {!code || expired ? (
        <View>
          <Text className="text-muted-text text-sm mb-3">
            {expired
              ? "Code expired — generate a fresh one."
              : "Pair without typing a vault ID."}
          </Text>
          <Pressable
            className="self-start rounded-lg bg-accent border border-hairline-accent px-4 py-2.5 items-center"
            onPress={handleGenerate}
            disabled={pairing.isPending}
          >
            <Text className="text-primary-text text-sm font-medium">
              {pairing.isPending ? "Generating…" : "Connect browser extension"}
            </Text>
          </Pressable>
        </View>
      ) : (
        <View>
          <View className="bg-surface rounded-lg p-3 items-center mb-2 self-start min-w-40">
            <Text className="text-primary-text text-2xl font-bold tracking-[0.3em]">
              {code}
            </Text>
          </View>
          <Text className="text-muted-text text-sm mb-2">
            Expires in {Math.floor(remaining / 60)}:{String(remaining % 60).padStart(2, "0")} — single use
          </Text>
          <Text className="text-muted-text text-sm mb-3">
            In the extension, enter this code. Your master password is still required there.
          </Text>
          <Pressable
            className="self-start rounded-lg bg-accent border border-hairline-accent px-4 py-2.5 items-center"
            onPress={handleGenerate}
            disabled={pairing.isPending}
          >
            <Text className="text-primary-text text-sm">
              {pairing.isPending ? "Generating…" : "Generate a new code"}
            </Text>
          </Pressable>
        </View>
      )}
      {error && <Text className="text-red-400 text-xs mt-2">{error}</Text>}
    </View>
  );
}
