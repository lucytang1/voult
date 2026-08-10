import { useAppStore, updateDecryptedVault, addVaultItem, updateVaultItem, deleteVaultItem } from "@/src/lib/state";
import { useEffect, useState, useMemo } from "react";
import { Pressable, Text, TextInput, View, ScrollView, Modal, Alert, Platform } from "react-native";
import { getAuthVerifierB64, decrypt, encrypt } from "../../lib/crypto/index.web";
import { useGetVault } from "../../lib/queries/vault/query";
import type { DecryptedVault, VaultItem } from "../../lib/state/type";
import { UpdateVaultItem, CreateVaultItem, DeleteVaultItem } from "@/src/lib/sync/type";
import { CreateIntentPayload } from "@/src/lib/sqlite/web/services/intent-service";
import { b64 } from "../../lib/crypto/index.web";
import { createIntent } from "@/src/lib/sqlite/web/services/intent-service";
import { syncScheduler } from "../../lib/sync/sync-scheduler";
import { v4 as uuidv4 } from "uuid";

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

export default function Home() {
  const encryptionKey = useAppStore((state) => state.encryptionKey);
  const authKey = useAppStore((state) => state.authKey);
  const isSyncing = useAppStore((state) => state.isSyncing);
  const [userKeyB64, setUserKeyB64] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedItem, setSelectedItem] = useState<VaultItem | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  // Add form state
  const [newSite, setNewSite] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");

  // Edit form state
  const [editSite, setEditSite] = useState("");
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");

  const handleCreate = async (site: string, username: string, password: string) => {
    if (!encryptionKey) return;
    const itemWithId: CreateVaultItem = { id: uuidv4(), site, username, password };
    const { cipher, iv } = await encrypt(JSON.stringify(itemWithId), encryptionKey);
    const intent: CreateIntentPayload = {
      payload: b64(cipher),
      payloadIv: b64(iv),
      deviceId: "test_device_id",
    }
    const { result, rows } = await createIntent("create", intent);
    if (result) {
      addVaultItem(itemWithId);
      syncScheduler.requestSync("intent-created");
    }
    console.log("createIntent ", result, rows);
    setShowAddModal(false);
    setNewSite("");
    setNewUsername("");
    setNewPassword("");
  }

  const handleUpdate = async (item: VaultItem) => {
    if (!encryptionKey) return;
    const updatedItem: UpdateVaultItem = {
      id: item.id,
      fields: {
        site: editSite || item.site,
        username: editUsername || item.username,
        password: editPassword || item.password,
      }
    };
    const { cipher, iv } = await encrypt(JSON.stringify(updatedItem), encryptionKey);
    const intent: CreateIntentPayload = {
      payload: b64(cipher),
      payloadIv: b64(iv),
      deviceId: "test_device_id",
    }
    const { result } = await createIntent("update", intent);
    if (result) {
      updateVaultItem(updatedItem);
      syncScheduler.requestSync("intent-created");
    }
    setShowEditModal(false);
  }

  const handleDelete = async (item: VaultItem) => {
    if (!encryptionKey) return;
    const { cipher, iv } = await encrypt(JSON.stringify({ id: item.id }), encryptionKey);
    const intent: CreateIntentPayload = {
      payload: b64(cipher),
      payloadIv: b64(iv),
      deviceId: "test_device_id",
    }
    const { result } = await createIntent("delete", intent);
    if (result) {
      deleteVaultItem({ id: item.id });
      syncScheduler.requestSync("intent-created");
      setSelectedItem(null);
    }
    setShowDeleteConfirm(false);
  }

  useEffect(() => {
    if (!authKey) {
      setUserKeyB64(null);
      return;
    }
    getAuthVerifierB64(authKey).then(setUserKeyB64);
  }, [authKey]);

  const getVault = useGetVault(
    {
      email: globalThis.localStorage.getItem("email") || "",
      user_key: userKeyB64 ?? "",
    },
    { enabled: !!userKeyB64 }
  );

  const vaultData = getVault.data?.vault;
  useEffect(() => {
    if (!vaultData || !encryptionKey) return;
    decrypt(vaultData.vault, vaultData.vaultiv, encryptionKey)
      .then((plain) => {
        const parsed = JSON.parse(plain) as DecryptedVault;
        updateDecryptedVault(parsed);
        console.log("decryptedVault", parsed);
      })
      .catch((err) => console.error("Failed to decrypt vault", err));
  }, [vaultData, encryptionKey]);

  const decryptedVault = useAppStore((state) => state.decryptedVault);

  const filteredItems = useMemo(() => {
    if (!decryptedVault?.items) return [];
    if (!searchQuery) return decryptedVault.items;
    const q = searchQuery.toLowerCase();
    return decryptedVault.items.filter(
      (item) =>
        item.site.toLowerCase().includes(q) ||
        item.username.toLowerCase().includes(q)
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
    <View className="flex-1 flex-row bg-[#1a1a2e]">
      {/* Left Sidebar - Vaults */}
      <View className="w-56 bg-[#16162a] border-r border-[#2a2a4a] flex-col">
        {/* Logo */}
        <View className="px-4 py-4 border-b border-[#2a2a4a]">
          <Text className="text-lg font-bold text-white flex items-center">
            <Text className="text-purple-400 mr-2">●</Text>
            Voult
          </Text>
        </View>

        {/* Vaults Header */}
        <View className="px-4 py-3 flex-row justify-between items-center">
          <Text className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Vaults</Text>
          <Pressable onPress={() => setShowAddModal(true)}>
            <Text className="text-gray-400 hover:text-white text-lg">+</Text>
          </Pressable>
        </View>

        {/* Vault Items */}
        <View className="px-2">
          <Pressable className="flex-row items-center px-3 py-2 rounded-lg bg-[#2a2a4a]">
            <Text className="text-white mr-3 text-lg">◇</Text>
            <View className="flex-1">
              <Text className="text-white text-sm font-medium">All items</Text>
              <Text className="text-gray-400 text-xs">{decryptedVault?.items?.length || 0} items</Text>
            </View>
          </Pressable>
        </View>

        {/* Bottom Actions */}
        <View className="mt-auto border-t border-[#2a2a4a] px-2 py-3 space-y-1">
          <Pressable className="flex-row items-center px-3 py-2 rounded-lg hover:bg-[#2a2a4a]">
            <Text className="text-gray-400 mr-3">🔒</Text>
            <Text className="text-gray-300 text-sm">Lock Voult</Text>
          </Pressable>
          <Pressable
            className="flex-row items-center px-3 py-2 rounded-lg hover:bg-[#2a2a4a]"
            disabled={isSyncing}
            onPress={() => syncScheduler.requestSync("forced")}
          >
            <Text className="text-gray-400 mr-3">🔄</Text>
            <Text className="text-gray-300 text-sm">{isSyncing ? "Syncing..." : "Sync"}</Text>
          </Pressable>
        </View>

        {/* User Info */}
        <View className="border-t border-[#2a2a4a] px-4 py-3">
          <Text className="text-white text-sm truncate">
            {globalThis.localStorage.getItem("email") || "user@example.com"}
          </Text>
          <Text className="text-gray-400 text-xs">Free</Text>
        </View>
      </View>

      {/* Middle Panel - Password List */}
      <View className="flex-1 flex-col bg-[#1e1e36]">
        {/* Search Bar */}
        <View className="px-4 py-3 border-b border-[#2a2a4a]">
          <View className="flex-row items-center bg-[#2a2a4a] rounded-lg px-3 py-2">
            <Text className="text-gray-400 mr-2">🔍</Text>
            <TextInput
              className="flex-1 text-white"
              placeholder="Search in all items..."
              placeholderTextColor="#666"
              value={searchQuery}
              onChangeText={setSearchQuery}
            />
          </View>
        </View>

        {/* Filter Tabs */}
        <View className="px-4 py-2 flex-row border-b border-[#2a2a4a]">
          <Pressable className="px-4 py-1 rounded-full bg-purple-600 mr-2">
            <Text className="text-white text-sm font-medium">All ({filteredItems.length})</Text>
          </Pressable>
          <Pressable className="px-4 py-1 rounded-full border border-[#4a4a6a]">
            <Text className="text-gray-300 text-sm">Recent</Text>
          </Pressable>
        </View>

        {/* Password List */}
        <ScrollView className="flex-1 px-2 py-2">
          {!decryptedVault || !decryptedVault.items?.length ? (
            <View className="flex-1 items-center justify-center py-12">
              <Text className="text-gray-400 text-center">No items in your vault yet.</Text>
              <Pressable
                className="mt-4 px-4 py-2 bg-purple-600 rounded-lg"
                onPress={() => setShowAddModal(true)}
              >
                <Text className="text-white">Add your first item</Text>
              </Pressable>
            </View>
          ) : (
            Object.entries(groupedItems).map(([group, items]) =>
              items.length > 0 ? (
                <View key={group} className="mb-4">
                  <Text className="text-xs font-semibold text-gray-400 uppercase tracking-wider px-2 mb-2">
                    {group}
                  </Text>
                  {items.map((item, index) => (
                    <Pressable
                      key={`${item.site}-${item.username}-${index}`}
                      className={`flex-row items-center px-3 py-3 rounded-lg mb-1 ${
                        selectedItem?.site === item.site && selectedItem?.username === item.username
                          ? "bg-purple-600/20 border border-purple-500/30"
                          : "hover:bg-[#2a2a4a]"
                      }`}
                      onPress={() => setSelectedItem(item)}
                    >
                      <View className="w-10 h-10 rounded-full bg-[#3a3a5a] flex items-center justify-center mr-3">
                        <Text className="text-white font-semibold text-sm">
                          {getSiteIcon(item.site)}
                        </Text>
                      </View>
                      <View className="flex-1">
                        <Text className="text-white text-sm font-medium">{item.site}</Text>
                        <Text className="text-gray-400 text-xs">{item.username}</Text>
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
      <View className="w-96 bg-[#1a1a2e] border-l border-[#2a2a4a] flex-col">
        {selectedItem ? (
          <>
            {/* Header */}
            <View className="px-6 py-4 border-b border-[#2a2a4a] flex-row items-center justify-between">
              <View className="flex-1">
                <Text className="text-xl font-bold text-white">{selectedItem.site}</Text>
                <Text className="text-gray-400 text-sm">Personal</Text>
              </View>
              <View className="flex-row items-center space-x-2">
                <Pressable
                  className="px-3 py-1.5 bg-purple-600 rounded-lg flex-row items-center"
                  onPress={() => {
                    setEditSite(selectedItem.site);
                    setEditUsername(selectedItem.username);
                    setEditPassword(selectedItem.password);
                    setShowEditModal(true);
                  }}
                >
                  <Text className="text-white text-sm mr-1">✏️</Text>
                  <Text className="text-white text-sm">Edit</Text>
                </Pressable>
                <Pressable
                  className="px-3 py-1.5 bg-red-600/20 rounded-lg"
                  onPress={() => setShowDeleteConfirm(true)}
                >
                  <Text className="text-red-400 text-sm">🗑️</Text>
                </Pressable>
              </View>
            </View>

            {/* Details */}
            <ScrollView className="flex-1 px-6 py-4">
              {/* Email */}
              <View className="mb-4">
                <Text className="text-gray-400 text-xs mb-1 flex-row items-center">
                  <Text className="mr-1">✉️</Text> Email
                </Text>
                <View className="bg-[#2a2a4a] rounded-lg px-4 py-3">
                  <Text className="text-white">{selectedItem.username}</Text>
                </View>
              </View>

              {/* Password */}
              <View className="mb-4">
                <Text className="text-gray-400 text-xs mb-1 flex-row items-center">
                  <Text className="mr-1">🔑</Text> Password
                </Text>
                <View className="bg-[#2a2a4a] rounded-lg px-4 py-3 flex-row items-center justify-between">
                  <Text className="text-white">••••••••••••</Text>
                  <View className="flex-row items-center">
                    <View className="px-2 py-0.5 bg-yellow-500/20 rounded mr-2">
                      <Text className="text-yellow-400 text-xs">Weak</Text>
                    </View>
                    <Pressable>
                      <Text className="text-gray-400">👁️</Text>
                    </Pressable>
                  </View>
                </View>
              </View>

              {/* Websites */}
              <View className="mb-4">
                <Text className="text-gray-400 text-xs mb-1 flex-row items-center">
                  <Text className="mr-1">🌐</Text> Websites
                </Text>
                <View className="bg-[#2a2a4a] rounded-lg px-4 py-3">
                  <Text className="text-purple-400">https://{selectedItem.site}</Text>
                </View>
              </View>

              {/* Metadata */}
              <View className="border-t border-[#2a2a4a] pt-4 mt-4">
                <View className="mb-3">
                  <Text className="text-gray-400 text-xs flex-row items-center">
                    <Text className="mr-1">⚡</Text> Last autofill
                  </Text>
                  <Text className="text-gray-300 text-sm">Today at {new Date().getHours()}:{String(new Date().getMinutes()).padStart(2, '0')}</Text>
                </View>
                <View className="mb-3">
                  <Text className="text-gray-400 text-xs flex-row items-center">
                    <Text className="mr-1">✏️</Text> Last modified
                  </Text>
                  <Text className="text-gray-300 text-sm">Just now</Text>
                </View>
                <View>
                  <Text className="text-gray-400 text-xs flex-row items-center">
                    <Text className="mr-1">🆕</Text> Created
                  </Text>
                  <Text className="text-gray-300 text-sm">Just now</Text>
                </View>
              </View>
            </ScrollView>
          </>
        ) : (
          <View className="flex-1 items-center justify-center px-8">
            <Text className="text-gray-400 text-center text-lg mb-2">Select an item</Text>
            <Text className="text-gray-500 text-center text-sm">
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
          <View className="bg-[#1e1e36] rounded-xl p-6 w-96 border border-[#2a2a4a]">
            <Text className="text-xl font-bold text-white mb-4">Add New Item</Text>
            <TextInput
              className="w-full bg-[#2a2a4a] rounded-lg px-4 py-3 text-white mb-3"
              placeholder="Site name"
              placeholderTextColor="#666"
              value={newSite}
              onChangeText={setNewSite}
            />
            <TextInput
              className="w-full bg-[#2a2a4a] rounded-lg px-4 py-3 text-white mb-3"
              placeholder="Username / Email"
              placeholderTextColor="#666"
              value={newUsername}
              onChangeText={setNewUsername}
              autoCapitalize="none"
            />
            <TextInput
              className="w-full bg-[#2a2a4a] rounded-lg px-4 py-3 text-white mb-4"
              placeholder="Password"
              placeholderTextColor="#666"
              value={newPassword}
              onChangeText={setNewPassword}
              secureTextEntry
            />
            <View className="flex-row justify-end space-x-2">
              <Pressable
                className="px-4 py-2 rounded-lg"
                onPress={() => setShowAddModal(false)}
              >
                <Text className="text-gray-400">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-purple-600 rounded-lg"
                onPress={() => {
                  if (newSite && newUsername && newPassword) {
                    handleCreate(newSite, newUsername, newPassword);
                  }
                }}
              >
                <Text className="text-white font-medium">Add</Text>
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
          <View className="bg-[#1e1e36] rounded-xl p-6 w-96 border border-[#2a2a4a]">
            <Text className="text-xl font-bold text-white mb-4">Edit Item</Text>
            <TextInput
              className="w-full bg-[#2a2a4a] rounded-lg px-4 py-3 text-white mb-3"
              placeholder="Site name"
              placeholderTextColor="#666"
              value={editSite}
              onChangeText={setEditSite}
            />
            <TextInput
              className="w-full bg-[#2a2a4a] rounded-lg px-4 py-3 text-white mb-3"
              placeholder="Username / Email"
              placeholderTextColor="#666"
              value={editUsername}
              onChangeText={setEditUsername}
              autoCapitalize="none"
            />
            <TextInput
              className="w-full bg-[#2a2a4a] rounded-lg px-4 py-3 text-white mb-4"
              placeholder="Password"
              placeholderTextColor="#666"
              value={editPassword}
              onChangeText={setEditPassword}
              secureTextEntry
            />
            <View className="flex-row justify-end space-x-2">
              <Pressable
                className="px-4 py-2 rounded-lg"
                onPress={() => setShowEditModal(false)}
              >
                <Text className="text-gray-400">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-purple-600 rounded-lg"
                onPress={() => {
                  if (selectedItem && (editSite || editUsername || editPassword)) {
                    handleUpdate(selectedItem);
                  }
                }}
              >
                <Text className="text-white font-medium">Save</Text>
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
          <View className="bg-[#1e1e36] rounded-xl p-6 w-80 border border-[#2a2a4a]">
            <Text className="text-xl font-bold text-white mb-2">Delete Item</Text>
            <Text className="text-gray-400 mb-6">
              Are you sure you want to delete this item? This action cannot be undone.
            </Text>
            <View className="flex-row justify-end space-x-2">
              <Pressable
                className="px-4 py-2 rounded-lg"
                onPress={() => setShowDeleteConfirm(false)}
              >
                <Text className="text-gray-400">Cancel</Text>
              </Pressable>
              <Pressable
                className="px-4 py-2 bg-red-600 rounded-lg"
                onPress={() => {
                  if (selectedItem) {
                    handleDelete(selectedItem);
                  }
                }}
              >
                <Text className="text-white font-medium">Delete</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}
