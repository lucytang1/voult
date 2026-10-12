import { useAppStore, updateDecryptedVault, addVaultItem, updateVaultItem, deleteVaultItem } from "@/src/lib/state";
import { useEffect, useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Pressable, Text, TextInput, View, ScrollView, Modal, Image } from "react-native";
import { useQueryClient } from "@tanstack/react-query";
import { Shield, Lock as LockIcon, RefreshCw, Search, Pencil, Trash2, Mail, KeyRound, Eye, Globe, Zap, Clock, CalendarPlus, Settings } from "lucide-react";
import { decrypt, encrypt } from "../../lib/crypto/index.web";
import { useGetVault } from "../../lib/queries/vault/query";
import type { DecryptedVault, VaultItem } from "../../lib/state/type";
import { UpdateVaultItem, CreateVaultItem, DeleteVaultItem } from "@/src/lib/sync/type";
import { CreateIntentPayload } from "@/src/lib/sqlite/web/services/intent-service";
import { b64 } from "../../lib/crypto/index.web";
import { createIntent } from "@/src/lib/sqlite/web/services/intent-service";
import { syncScheduler } from "../../lib/sync/sync-scheduler";
import { getOrCreateDeviceKey } from "../../lib/crypto/device-key";
import { lockVaultNow } from "@/src/lib/auth/lock";
import { useAuthGuard } from "@/src/lib/auth/use-auth-guard";
import { useRouter } from "expo-router";
import { v4 as uuidv4 } from "uuid";
import { canonicalizeOrigin, normalizeAccount } from "@voult/vault-core";
import { faviconForItem } from "@voult/vault-core";
import { http } from "../../lib/queries/http";
import type { SsoProvider, SsoSignIn } from "@voult/vault-core";

// Device ids are cached per vault — a shared single value could attribute
// one vault's intents to another after a vault switch.
const cachedDeviceIds: Record<string, string> = {};
async function resolveDeviceId(vaultId: string) {
  if (!cachedDeviceIds[vaultId]) {
    const device = await getOrCreateDeviceKey(vaultId);
    cachedDeviceIds[vaultId] = device.device_id;
  }
  return cachedDeviceIds[vaultId];
}

type TimeGroup = "Today" | "Last week" | "More than a month";

function getTimeGroup(_item: VaultItem, index: number): TimeGroup {
  // Simulate time grouping based on index for demo
  if (index < 4) return "Today";
  if (index < 8) return "Last week";
  return "More than a month";
}

function getSiteIcon(site: string): string {
  if (site.includes("google")) return "G";
  if (site.includes("github")) return "GH";
  if (site.includes("spotify")) return "S";
  if (site.includes("facebook")) return "F";
  if (site.includes("proton")) return "P";
  return site.charAt(0).toUpperCase();
}

// Site icon for a vault item: the stored favicon captured by the extension at
// save time, else `<origin>/favicon.ico` when the item is origin-bound, else
// the legacy letter tile. Icons load through the same-origin /api/favicon
// proxy — the app's COEP `require-corp` header makes the browser refuse
// cross-origin `<img>` loads, and favicon hosts don't send CORP. A failed
// load permanently falls back to the letter for that item (per render) so
// dead icons never leave blank rows. Icons are display-only — matching never
// consults them.
function SiteIcon({
  item,
  vaultId,
  size = 40,
}: {
  item: VaultItem;
  vaultId: string;
  size?: number;
}) {
  const [imageFailed, setImageFailed] = useState(false);
  const direct = faviconForItem(item);
  useEffect(() => setImageFailed(false), [direct]);
  const iconQuery = useQuery({
    queryKey: ["favicon", vaultId, direct ?? ""],
    enabled: !!direct,
    staleTime: 24 * 60 * 60 * 1000,
    queryFn: async () => {
    // Fetch through the shared credentialed API client instead of assigning
    // the proxy URL directly to <Image>. Browser image requests use
    // credentialsMode="same-origin" and omit the session cookie in split-port
    // dev (Expo :8081 → API :8080), so the authenticated proxy otherwise 401s.
    // Converting the response to a data URL also means the final image load is
    // same-document and is not blocked by COEP require-corp.
      const response = await http.get<ArrayBuffer>(`/favicon?u=${encodeURIComponent(direct!)}`, {
        responseType: "arraybuffer",
      });
      const contentType = String(response.headers["content-type"] ?? "image/png");
      const bytes = new Uint8Array(response.data);
      let binary = "";
      // Chunk to avoid overflowing the JS argument stack on a large icon.
      for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      }
      return `data:${contentType};base64,${btoa(binary)}`;
    },
  });

  const src = iconQuery.data;
  if (!direct || iconQuery.isError || imageFailed) {
    return (
      <View
        className="rounded-xl bg-transparent flex items-center justify-center mr-3"
        style={{ width: size, height: size }}
      >
        <Text className="text-muted-text font-semibold text-sm">
          {getSiteIcon(item.site)}
        </Text>
      </View>
    );
  }
  if (!src) {
    // Keep the reserved space visually quiet while the icon query resolves;
    // the query cache avoids refetching icons as rows rerender or remount.
    return <View className="mr-3" style={{ width: size, height: size }} />;
  }
  return (
    <View
      className="rounded-xl bg-transparent flex items-center justify-center mr-3 overflow-hidden"
      style={{ width: size, height: size }}
    >
      <Image
        source={{ uri: src }}
        style={{ width: size - 12, height: size - 12, borderRadius: 9999 }}
        onError={() => setImageFailed(true)}
      />
    </View>
  );
}

// Short label for an SSO provider ("Google", "GitHub", …). Duplicated from
// the extension's messaging helper (client must not import extension code).
function ssoLabel(p?: SsoProvider): string {
  switch (p) {
    case "google": return "Google";
    case "github": return "GitHub";
    case "apple": return "Apple";
    case "microsoft": return "Microsoft";
    default: return "SSO";
  }
}

// A sign-in method names the account it authenticates when one is known
// ("Google · alice@gmail.com"); a provider-only method — stored by the
// extension when the vault held no account for that provider — names just the
// sign-in itself ("Google"), because that is all it records.
function ssoMethodLabel(s: SsoSignIn): string {
  return s.account ? `${ssoLabel(s.provider)} · ${s.account}` : ssoLabel(s.provider);
}

const SSO_PROVIDERS: SsoProvider[] = ["google", "github", "apple", "microsoft", "custom"];

// Placeholder for a provider's account field. GitHub and other handle-based
// IdPs authenticate a handle, not an address, so the hint has to allow both.
function ssoAccountPlaceholder(p: SsoProvider): string {
  return p === "github" || p === "custom" ? "username or handle" : "you@example.com";
}

/** provider → account draft. A key means "this method is enabled". */
type SsoDraft = Partial<Record<SsoProvider, string>>;

/**
 * Turns the provider→account draft into sign-in methods. An empty account
 * yields a provider-only method, which is a legitimate stored state (the
 * extension saves it whenever it cannot know the IdP account), so the form
 * accepts it rather than blocking the save: the user is choosing to remember
 * HOW to sign in without saying which account.
 */
function ssoMethodsFrom(draft: SsoDraft): SsoSignIn[] {
  const methods: SsoSignIn[] = [];
  for (const p of SSO_PROVIDERS) {
    if (!(p in draft)) continue;
    methods.push({ provider: p, account: (draft[p] ?? "").trim() });
  }
  return methods;
}

/**
 * Resolves the identity (`username`) an item will be saved with. One item =
 * one account, so when SSO names an account and no site account was typed, the
 * IdP account IS the identity. Returns null when the typed site account and the
 * first SSO account disagree — those are two different accounts and must be
 * saved as two items. A provider-only method names no identity, so it never
 * constrains one: the typed site account (if any) stands on its own.
 */
function resolveIdentity(
  username: string,
  methods: SsoSignIn[],
): { username: string | undefined; error: string | null } {
  const typed = username.trim();
  const first = methods[0]?.account ?? "";
  if (methods.length === 0 || !first) return { username: typed || undefined, error: null };
  if (!typed) return { username: first, error: null };
  if (normalizeAccount(typed) !== normalizeAccount(first)) {
    return {
      username: undefined,
      error: `${typed} and ${first} are different accounts — save them as two items.`,
    };
  }
  return { username: first, error: null };
}

/** Provider picker + one account field per selected provider. Shared by the
 *  add and edit modals so both stay in lockstep. */
function SsoMethodEditor({
  draft,
  onChange,
}: {
  draft: SsoDraft;
  onChange: (next: SsoDraft) => void;
}) {
  const selected = SSO_PROVIDERS.filter((p) => p in draft);
  return (
    <View className="mb-4">
      <Text className="text-muted-text text-xs mb-2">Continue with (optional)</Text>
      <View className="flex-row flex-wrap gap-2">
        {SSO_PROVIDERS.map((p) => {
          const active = p in draft;
          return (
            <Pressable
              key={p}
              className={`px-3 py-2 rounded-lg ${active ? "bg-accent-line" : "bg-surface"}`}
              onPress={() => {
                const next = { ...draft };
                if (active) delete next[p];
                else next[p] = "";
                onChange(next);
              }}
            >
              <Text className={active ? "text-primary-text font-medium" : "text-muted-text"}>
                {ssoLabel(p)}
              </Text>
            </Pressable>
          );
        })}
      </View>
      {selected.map((p) => (
        <View key={p} className="mt-3">
          <Text className="text-muted-text text-xs mb-1">{ssoLabel(p)} account</Text>
          <TextInput
            className="w-full bg-surface rounded-lg px-4 py-3 text-primary-text"
            placeholder={ssoAccountPlaceholder(p)}
            placeholderTextColor="#666"
            value={draft[p] ?? ""}
            onChangeText={(t) => onChange({ ...draft, [p]: t })}
            autoCapitalize="none"
            autoCorrect={false}
          />
        </View>
      ))}
      {selected.length > 0 && (
        <Text className="text-muted-text text-xs mt-2">
          The account you sign in with there — that's what tells this login apart. Leave it
          blank to remember just the sign-in method.
        </Text>
      )}
    </View>
  );
}

export default function Home() {
  const vaultKey = useAppStore((state) => state.vaultKey);
  const session = useAppStore((state) => state.session);
  const isLocked = useAppStore((state) => state.isLocked);
  const isSyncing = useAppStore((state) => state.isSyncing);
  const router = useRouter();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedItem, setSelectedItem] = useState<VaultItem | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  // Add form state
  const [newSite, setNewSite] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  // "Continue with X" methods linked to the new login, each with the account it
  // authenticates. A login is one account with every sign-in option: password
  // (when set) plus any methods here.
  const [newSso, setNewSso] = useState<SsoDraft>({});
  const [newSsoError, setNewSsoError] = useState<string | null>(null);
  // Validated sign-in methods for the add form. Null while any selected
  // provider has no account yet, which blocks the save.
  const newSsoMethods = useMemo(() => ssoMethodsFrom(newSso), [newSso]);

  // Edit form state
  const [editSite, setEditSite] = useState("");
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editSso, setEditSso] = useState<SsoDraft>({});
  const [editSsoError, setEditSsoError] = useState<string | null>(null);
  // Validated sign-in methods for the edit form. Null while any selected
  // provider has no account yet, which blocks the save.
  const editSsoMethods = useMemo(() => ssoMethodsFrom(editSso), [editSso]);

  // Home requires the unlocked state; the guard bounces
  // locked users to /lock and signed-out users to / (landing).
  useAuthGuard(["unlocked"]);

  /**
   * Lock: delegated to the shared lockVaultNow() so the sidebar button and the
   * autolock watchdog produce identical state (see lib/auth/lock.ts).
   */
  const handleLock = async () => {
    await lockVaultNow({ queryClient, vault: getVault.data?.vault ?? null, reason: "manual" });
  };

  const handleCreate = async (
    site: string,
    username: string,
    password: string,
    sso: SsoSignIn[],
  ) => {
    if (!vaultKey) return;
    // Best-effort origin binding for future autofill matching: when the site
    // field parses as an origin, store it; otherwise leave origin unset (the
    // M1 form will capture it explicitly). Never let a parse failure block save.
    let origin: string | undefined;
    try {
      origin = canonicalizeOrigin(site);
    } catch {
      origin = undefined;
    }
    // One item = one account. The identity is the site username when given,
    // otherwise the IdP account the item signs in with.
    const identity = resolveIdentity(username, sso);
    if (identity.error) {
      setNewSsoError(identity.error);
      return;
    }
    // One item carries every sign-in option: an optional stored password plus
    // zero or more SSO methods. Passwordless SSO-only items simply omit the
    // secret; callers must pass a password and/or at least one method.
    const itemWithId: CreateVaultItem = {
      id: uuidv4(),
      site,
      username: identity.username,
      password: password || undefined,
      sso,
      origin,
    };
    const { cipher, iv } = await encrypt(JSON.stringify(itemWithId), vaultKey);
    const intent: CreateIntentPayload = {
      payload: b64(cipher),
      payloadIv: b64(iv),
      deviceId: await resolveDeviceId(session!.vaultId),
    }
    const { result } = await createIntent("create", intent);
    if (result) {
      addVaultItem(itemWithId);
      syncScheduler.requestSync("intent-created");
    }
    // No result logging: rows carry ciphertext.
    setShowAddModal(false);
    setNewSite("");
    setNewUsername("");
    setNewPassword("");
    setNewSso({});
    setNewSsoError(null);
  }

  const handleUpdate = async (item: VaultItem) => {
    if (!vaultKey) return;
    // Re-validate here rather than trusting the caller: this is the last point
    // before encrypt, and a site account that contradicts the IdP account must
    // be caught rather than silently saved as a second identity.
    const methods = ssoMethodsFrom(editSso);
    const identity = resolveIdentity(editUsername, methods);
    if (identity.error) {
      setEditSsoError(identity.error);
      return;
    }
    // Per-field LWW: the sso set rides as a full-set replacement alongside
    // site/username/password. Clearing the password field keeps the stored
    // value (empty edit ≠ delete); the sso set is authoritative from the form.
    const updatedItem: UpdateVaultItem = {
      id: item.id,
      fields: {
        site: editSite || item.site,
        username: identity.username ?? item.username,
        password: editPassword || item.password,
        sso: methods,
      },
    };
    const { cipher, iv } = await encrypt(JSON.stringify(updatedItem), vaultKey);
    const intent: CreateIntentPayload = {
      payload: b64(cipher),
      payloadIv: b64(iv),
      deviceId: await resolveDeviceId(session!.vaultId),
    }
    const { result } = await createIntent("update", intent);
    if (result) {
      updateVaultItem(updatedItem);
      syncScheduler.requestSync("intent-created");
    }
    setShowEditModal(false);
  }

  const handleDelete = async (item: VaultItem) => {
    if (!vaultKey) return;
    const { cipher, iv } = await encrypt(JSON.stringify({ id: item.id }), vaultKey);
    const intent: CreateIntentPayload = {
      payload: b64(cipher),
      payloadIv: b64(iv),
      deviceId: await resolveDeviceId(session!.vaultId),
    }
    const { result } = await createIntent("delete", intent);
    if (result) {
      deleteVaultItem({ id: item.id });
      syncScheduler.requestSync("intent-created");
      setSelectedItem(null);
    }
    setShowDeleteConfirm(false);
  }

  const getVault = useGetVault({
    enabled: !!vaultKey && !isLocked && !!session,
  }, session?.vaultId);

  const vaultData = getVault.data?.vault;
  useEffect(() => {
    if (!vaultData || !vaultKey) return;
    decrypt(vaultData.vault, vaultData.vaultiv, vaultKey)
      .then((plain) => {
        const parsed = JSON.parse(plain) as DecryptedVault;
        updateDecryptedVault(parsed);
        // Never log the decrypted vault: it holds plaintext passwords.
      })
      .catch((err) => console.error("Failed to decrypt vault", err));
  }, [vaultData, vaultKey]);

  const decryptedVault = useAppStore((state) => state.decryptedVault);

  const filteredItems = useMemo(() => {
    if (!decryptedVault?.items) return [];
    if (!searchQuery) return decryptedVault.items;
    const q = searchQuery.toLowerCase();
    return decryptedVault.items.filter(
      (item) =>
        item.site.toLowerCase().includes(q) ||
        (item.username ?? "").toLowerCase().includes(q) ||
        // Search by provider ("google") and by IdP account, so finding a login
        // works whether the user remembers which side of it they know.
        (item.sso ?? [])
          .map((s) => `${ssoLabel(s.provider)} ${s.account}`.trim())
          .join(" ")
          .toLowerCase()
          .includes(q)
    );
  }, [decryptedVault?.items, searchQuery]);

  const groupedItems = useMemo(() => {
    const groups: Record<TimeGroup, VaultItem[]> = {
      "Today": [],
      "Last week": [],
      "More than a month": [],
    };
    filteredItems.forEach((item, index) => {
      const group = getTimeGroup(item, index);
      groups[group].push(item);
    });
    return groups;
  }, [filteredItems]);

  return (
    <View className="flex-1 flex-row">
      {/* Left Sidebar - Vaults */}
      <View className="w-56 bg-ground border-r border-border flex-col">
        {/* Logo */}
        <View className="px-4 py-4  flex-row items-center">
          <Shield size={20} color="#D89AC6" style={{ marginRight: 8 }} />
          <Text className="text-lg font-bold text-primary-text">Voult</Text>
        </View>

        {/* Vaults Header */}
        <View className="px-4 py-3 flex-row justify-between items-center">
          <Text className="text-xs font-semibold text-muted-text uppercase tracking-wider">Vaults</Text>
          <Pressable onPress={() => setShowAddModal(true)}>
            <Text className="text-muted-text hover:text-primary-text text-lg">+</Text>
          </Pressable>
        </View>

        {/* Vault Items */}
        <View className="px-2">
          <Pressable className="flex-row items-center px-3 py-2 rounded-lg bg-surface">
            <Shield size={16} color="#fff" style={{ marginRight: 12 }} />
            <View className="flex-1">
              <Text className="text-primary-text text-sm font-medium">All items</Text>
              <Text className="text-muted-text text-xs">{decryptedVault?.items?.length || 0} items</Text>
            </View>
          </Pressable>
        </View>

        {/* Bottom Actions */}
        <View className="mt-auto border-t px-2 py-3 space-y-1">
          <Pressable
            className="flex-row items-center px-3 py-2 rounded-lg hover:bg-surface"
            onPress={handleLock}
          >
            <LockIcon size={16} color="#9ca3af" style={{ marginRight: 12 }} />
            <Text className="text-muted-text text-sm">Lock Voult</Text>
          </Pressable>
          <Pressable
            className="flex-row items-center px-3 py-2 rounded-lg hover:bg-surface"
            disabled={isSyncing}
            onPress={() => syncScheduler.requestSync("forced")}
          >
            <RefreshCw size={16} color="#9ca3af" style={{ marginRight: 12 }} />
            <Text className="text-muted-text text-sm">{isSyncing ? "Syncing..." : "Sync"}</Text>
          </Pressable>
        </View>

        {/* Current vault */}
        <View className="border-t  px-4 py-3">
          <View className="flex-row items-center">
            <View className="flex-1 min-w-0">
              <Text className="text-primary-text text-sm truncate">
                {session?.vaultId ? `Vault ${session.vaultId.slice(0, 8)}…` : ""}
              </Text>
              <Text className="text-muted-text text-xs">Free</Text>
            </View>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Settings"
              className="ml-2 p-2 rounded-lg hover:bg-surface"
              onPress={() => router.push("/settings" as any)}
            >
              <Settings size={17} color="#9ca3af" />
            </Pressable>
          </View>
        </View>
      </View>

      {/* Middle Panel - Password List */}
      <View className="flex-1 flex-col bg-ground">
        {/* Search Bar */}
        <View className="px-4 py-3 border-b border-border">
          <View className="flex-row items-center bg-surface rounded-lg px-3 py-2">
            <Search size={16} color="#9ca3af" style={{ marginRight: 8 }} />
            <TextInput
              className="flex-1 text-primary-text"
              placeholder="Search in all items..."
              placeholderTextColor="#666"
              value={searchQuery}
              onChangeText={setSearchQuery}
            />
          </View>
        </View>

        {/* Filter Tabs */}
        <View className="px-4 py-2 flex-row border-b border-border">
          <Pressable className="px-4 py-1 rounded-full bg-surface border border-border-strong mr-2">
            <Text className="text-primary-text text-sm font-medium">All ({filteredItems.length})</Text>
          </Pressable>
          <Pressable className="px-4 py-1 rounded-full border border-border-strong">
            <Text className="text-muted-text text-sm">Recent</Text>
          </Pressable>
        </View>

        {/* Password List */}
        <ScrollView className="flex-1 px-2 py-2">
          {!decryptedVault || !decryptedVault.items?.length ? (
            <View className="flex-1 items-center justify-center py-12">
              <Text className="text-muted-text text-center">No items in your vault yet.</Text>
              <Pressable
                className="mt-4 px-4 py-2 bg-surface border border-border-strong rounded-lg"
                onPress={() => setShowAddModal(true)}
              >
                <Text className="text-primary-text">Add your first item</Text>
              </Pressable>
            </View>
          ) : (
            Object.entries(groupedItems).map(([group, items]) =>
              items.length > 0 ? (
                <View key={group} className="mb-4">
                  <Text className="text-xs font-semibold text-muted-text uppercase tracking-wider px-2 mb-2">
                    {group}
                  </Text>
                  {items.map((item) => (
                    <Pressable
                      key={item.id}
                      className={`flex-row items-center px-3 py-3 rounded-lg mb-1 ${
                        selectedItem?.id === item.id
                          ? "bg-accent-line/15 border border-accent-line/40"
                          : "hover:bg-surface"
                      }`}
                      onPress={() => setSelectedItem(item)}
                    >
                      <SiteIcon item={item} vaultId={session!.vaultId} />
                      <View className="flex-1">
                        <Text className="text-primary-text text-sm font-medium">{item.site}</Text>
                        <Text className="text-muted-text text-xs">
                          {[
                            item.username ?? "",
                            // Provider as a suffix, not "Continue with X": the
                            // account above is the identity, this says how it
                            // signs in.
                            (item.sso ?? []).map((s) => ssoLabel(s.provider)).join(", "),
                          ]
                            .filter(Boolean)
                            .join(" · ") || "No sign-in method"}
                        </Text>
                      </View>
                    </Pressable>
                  ))}
                </View>
              ) : null
            )
          )}
        </ScrollView>
      </View>

      {/* Right Panel - Detail View */}
      <View className="w-96 bg-panel border-l border-border flex-col">
        {selectedItem ? (
          <>
            {/* Header */}
            <View className="px-6 py-4 border-b border-border flex-row items-center justify-between">
              <View className="flex-1 flex-row items-center">
                <SiteIcon item={selectedItem} vaultId={session!.vaultId} size={44} />
                <View className="flex-1">
                  <Text className="text-xl font-bold text-primary-text">{selectedItem.site}</Text>
                  <Text className="text-muted-text text-sm">Personal</Text>
                </View>
              </View>
              <View className="flex-row items-center space-x-2">
                <Pressable
                  className="px-3 py-1.5 bg-surface border border-border-strong rounded-lg flex-row items-center"
                  onPress={() => {
                    setEditSite(selectedItem.site);
                    setEditUsername(selectedItem.username ?? "");
                    setEditPassword(selectedItem.password ?? "");
                    setEditSso(
                      Object.fromEntries(
                        (selectedItem.sso ?? []).map((s) => [s.provider, s.account]),
                      ) as SsoDraft,
                    );
                    setEditSsoError(null);
                    setShowEditModal(true);
                  }}
                >
                  <Pencil size={14} color="#fff" style={{ marginRight: 4 }} />
                  <Text className="text-primary-text text-sm">Edit</Text>
                </Pressable>
                <Pressable
                  className="px-3 py-1.5 bg-red-600/20 rounded-lg items-center justify-center"
                  onPress={() => setShowDeleteConfirm(true)}
                >
                  <Trash2 size={16} color="#f87171" />
                </Pressable>
              </View>
            </View>

            {/* Details */}
            <ScrollView className="flex-1 px-6 py-4">
              {/* Site account: only meaningful when the site itself issued a credential.
                  An SSO-only login's identity IS the IdP account, shown below —
                  repeating it here would say the same thing twice. */}
              {selectedItem.password && (
                <View className="mb-4">
                  <View className="flex-row items-center mb-1">
                    <Mail size={12} color="#9ca3af" style={{ marginRight: 4 }} />
                    <Text className="text-muted-text text-xs">Site account</Text>
                  </View>
                  <View className="bg-surface rounded-lg px-4 py-3">
                    <Text className="text-primary-text">{selectedItem.username ?? "—"}</Text>
                  </View>
                </View>
              )}

              {/* Sign-in methods: each names the provider AND the account it
                  authenticates, so "Continue with Google" always resolves to a
                  specific identity. */}
              {(selectedItem.sso ?? []).length > 0 && (
                <View className="mb-4">
                  <View className="flex-row items-center mb-1">
                    <KeyRound size={12} color="#9ca3af" style={{ marginRight: 4 }} />
                    <Text className="text-muted-text text-xs">Sign-in methods</Text>
                  </View>
                  <View className="bg-green-900/30 border border-green-500/20 rounded-lg px-4 py-3">
                    {(selectedItem.sso ?? []).map((s) => (
                      <Text key={`${s.provider}:${s.account}`} className="text-green-300 font-medium">
                        {ssoMethodLabel(s)}
                      </Text>
                    ))}
                    {!selectedItem.password && (
                      <Text className="text-muted-text text-xs mt-1">No password stored — use the site's sign-in button.</Text>
                    )}
                  </View>
                </View>
              )}
              {selectedItem.password ? (
              <View className="mb-4">
                <View className="flex-row items-center mb-1">
                  <KeyRound size={12} color="#9ca3af" style={{ marginRight: 4 }} />
                  <Text className="text-muted-text text-xs">Password</Text>
                </View>
                <View className="bg-surface rounded-lg px-4 py-3 flex-row items-center justify-between">
                  <Text className="text-primary-text">••••••••••••</Text>
                  <View className="flex-row items-center">
                    <View className="px-2 py-0.5 bg-yellow-500/20 rounded mr-2">
                      <Text className="text-yellow-400 text-xs">Weak</Text>
                    </View>
                    <Pressable>
                      <Eye size={16} color="#9ca3af" />
                    </Pressable>
                  </View>
                </View>
              </View>
              ) : (selectedItem.sso ?? []).length === 0 && (
              <View className="mb-4">
                <View className="flex-row items-center mb-1">
                  <KeyRound size={12} color="#9ca3af" style={{ marginRight: 4 }} />
                  <Text className="text-muted-text text-xs">Password</Text>
                </View>
                <View className="bg-surface rounded-lg px-4 py-3 flex-row items-center justify-between">
                  <Text className="text-muted-text">No password stored</Text>
                </View>
              </View>
              )}

              {/* Websites */}
              <View className="mb-4">
                <View className="flex-row items-center mb-1">
                  <Globe size={12} color="#9ca3af" style={{ marginRight: 4 }} />
                  <Text className="text-muted-text text-xs">Websites</Text>
                </View>
                <View className="bg-surface rounded-lg px-4 py-3">
                  <Text className="text-accent-text">https://{selectedItem.site}</Text>
                </View>
              </View>

              {/* Metadata */}
              <View className="border-t border-border pt-4 mt-4">
                <View className="mb-3">
                  <View className="flex-row items-center">
                    <Zap size={12} color="#9ca3af" style={{ marginRight: 4 }} />
                    <Text className="text-muted-text text-xs">Last autofill</Text>
                  </View>
                  <Text className="text-muted-text text-sm">Today at {new Date().getHours()}:{String(new Date().getMinutes()).padStart(2, '0')}</Text>
                </View>
                <View className="mb-3">
                  <View className="flex-row items-center">
                    <Pencil size={12} color="#9ca3af" style={{ marginRight: 4 }} />
                    <Text className="text-muted-text text-xs">Last modified</Text>
                  </View>
                  <Text className="text-muted-text text-sm">Just now</Text>
                </View>
                <View>
                  <View className="flex-row items-center">
                    <CalendarPlus size={12} color="#9ca3af" style={{ marginRight: 4 }} />
                    <Text className="text-muted-text text-xs">Created</Text>
                  </View>
                  <Text className="text-muted-text text-sm">Just now</Text>
                </View>
              </View>
            </ScrollView>
          </>
        ) : (
          <View className="flex-1 items-center justify-center px-8">
            <Text className="text-muted-text text-center text-lg mb-2">Select an item</Text>
            <Text className="text-muted-text text-center text-sm">
              Choose a password from the list to view its details
            </Text>
          </View>
        )}
      </View>

      {/* Add Modal */}
      <Modal
        visible={showAddModal}
        transparent
        animationType="fade"
        onRequestClose={() => setShowAddModal(false)}
      >
        <View className="flex-1 bg-black/60 items-center justify-center">
          <View className="bg-card rounded-xl p-6 w-96 border border-border">
            <Text className="text-xl font-bold text-primary-text mb-4">Add New Item</Text>
            <Text className="text-muted-text text-xs mb-3">One item holds every way to sign in — set a password, link SSO, or both.</Text>
            <TextInput
              className="w-full bg-surface rounded-lg px-4 py-3 text-primary-text mb-3"
              placeholder="Site name"
              placeholderTextColor="#666"
              value={newSite}
              onChangeText={setNewSite}
            />
            <TextInput
              className="w-full bg-surface rounded-lg px-4 py-3 text-primary-text mb-3"
              placeholder="Account at this site (optional if SSO only)"
              placeholderTextColor="#666"
              value={newUsername}
              onChangeText={(t) => {
                setNewUsername(t);
                setNewSsoError(null);
              }}
              autoCapitalize="none"
            />
            <TextInput
              className="w-full bg-surface rounded-lg px-4 py-3 text-primary-text mb-3"
              placeholder="Password (optional if SSO linked)"
              placeholderTextColor="#666"
              value={newPassword}
              onChangeText={setNewPassword}
              secureTextEntry
            />
            <SsoMethodEditor
              draft={newSso}
              onChange={(next) => {
                setNewSso(next);
                setNewSsoError(null);
              }}
            />
            {newSsoError && (
              <Text className="text-red-400 text-xs mb-3">{newSsoError}</Text>
            )}
            {newSsoMethods === null && Object.keys(newSso).length > 0 && !newSsoError && (
              <Text className="text-muted-text text-xs mb-3">
                Enter the account for each selected provider.
              </Text>
            )}
            <View className="flex-row justify-end space-x-2">
              <Pressable
                className="px-4 py-2 rounded-lg"
                onPress={() => setShowAddModal(false)}
              >
                <Text className="text-muted-text">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-surface border border-border-strong rounded-lg"
                onPress={() => {
                  // One item, multiple sign-in options: require a site plus a
                  // password and/or at least one SSO method — and every chosen
                  // provider must name its account before it can be saved.
                  const methods = ssoMethodsFrom(newSso);
                  if (methods === null) {
                    setNewSsoError("Every selected provider needs an account — or unselect it.");
                    return;
                  }
                  if (newSite && (newPassword || methods.length > 0)) {
                    handleCreate(newSite, newUsername, newPassword, methods);
                  }
                }}
              >
                <Text className="text-primary-text font-medium">Add</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>

      {/* Edit Modal */}
      <Modal
        visible={showEditModal}
        transparent
        animationType="fade"
        onRequestClose={() => setShowEditModal(false)}
      >
        <View className="flex-1 bg-black/60 items-center justify-center">
          <View className="bg-card rounded-xl p-6 w-96 border border-border">
            <Text className="text-xl font-bold text-primary-text mb-4">Edit Item</Text>
            <TextInput
              className="w-full bg-surface rounded-lg px-4 py-3 text-primary-text mb-3"
              placeholder="Site name"
              placeholderTextColor="#666"
              value={editSite}
              onChangeText={setEditSite}
            />
            <TextInput
              className="w-full bg-surface rounded-lg px-4 py-3 text-primary-text mb-3"
              placeholder="Account at this site"
              placeholderTextColor="#666"
              value={editUsername}
              onChangeText={(t) => {
                setEditUsername(t);
                setEditSsoError(null);
              }}
              autoCapitalize="none"
            />
            <TextInput
              className="w-full bg-surface rounded-lg px-4 py-3 text-primary-text mb-3"
              placeholder="Password (empty keeps stored value)"
              placeholderTextColor="#666"
              value={editPassword}
              onChangeText={setEditPassword}
              secureTextEntry
            />
            <SsoMethodEditor
              draft={editSso}
              onChange={(next) => {
                setEditSso(next);
                setEditSsoError(null);
              }}
            />
            {editSsoError && (
              <Text className="text-red-400 text-xs mb-3">{editSsoError}</Text>
            )}
            <View className="flex-row justify-end space-x-2">
              <Pressable
                className="px-4 py-2 rounded-lg"
                onPress={() => setShowEditModal(false)}
              >
                <Text className="text-muted-text">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-surface border border-border-strong rounded-lg"
                onPress={() => {
                  // Same gate as add: a selected provider with no account is not
                  // a storable sign-in method.
                  if (editSsoMethods === null) {
                    setEditSsoError("Every selected provider needs an account — or unselect it.");
                    return;
                  }
                  if (
                    selectedItem &&
                    (editSite || editUsername || editPassword || editSsoMethods.length > 0 || (selectedItem.sso ?? []).length > 0)
                  ) {
                    handleUpdate(selectedItem);
                  }
                }}
              >
                <Text className="text-primary-text font-medium">Save</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        visible={showDeleteConfirm}
        transparent
        animationType="fade"
        onRequestClose={() => setShowDeleteConfirm(false)}
      >
        <View className="flex-1 bg-black/60 items-center justify-center">
          <View className="bg-card rounded-xl p-6 w-80 border border-border">
            <Text className="text-xl font-bold text-primary-text mb-2">Delete Item</Text>
            <Text className="text-muted-text mb-6">
              Are you sure you want to delete this item? This action cannot be undone.
            </Text>
            <View className="flex-row justify-end space-x-2">
              <Pressable
                className="px-4 py-2 rounded-lg"
                onPress={() => setShowDeleteConfirm(false)}
              >
                <Text className="text-muted-text">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-red-600 rounded-lg"
                onPress={() => {
                  if (selectedItem) {
                    handleDelete(selectedItem);
                  }
                }}
              >
                <Text className="text-primary-text font-medium">Delete</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}
