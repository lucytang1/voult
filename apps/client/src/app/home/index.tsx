import { useAppStore, updateDecryptedVault, addVaultItem } from "@/src/lib/state";
import { useEffect, useState } from "react";
import { Pressable, Text, TextInput, View, ScrollView } from "react-native";
import { getAuthVerifierB64, decrypt, encrypt } from "../../lib/crypto/index.web";
import { useGetVault } from "../../lib/queries/vault/query";
import type { DecryptedVault, VaultItem } from "../../lib/state/type";
import { operation_type } from "@/src/lib/sqlite/web/type";
import { CreateIntentPayload } from "@/src/lib/sqlite/web/services/intent-service";
import { b64 } from "../../lib/crypto/index.web";
import { createIntent } from "@/src/lib/sqlite/web/services/intent-service";
import { sync } from "../../lib/sync/index";
import { useQueryClient } from "@tanstack/react-query";


export default function Home() {
  const encryptionKey = useAppStore((state) => state.encryptionKey);
  const authKey = useAppStore((state) => state.authKey);
  const [userKeyB64, setUserKeyB64] = useState<string | null>(null);
  const [site, setSite] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const queryClient = useQueryClient();

  const handleCreate = async (vaultItem: VaultItem) => {
    if (!encryptionKey) return;
    const { cipher, iv } = await encrypt(JSON.stringify(vaultItem), encryptionKey);
    const intent: CreateIntentPayload = {
      payload: b64(cipher),
      payloadIv: b64(iv),
      deviceId: "test_device_id",
    }
    const { result, rows } = await createIntent(intent);
    if (result) {
      addVaultItem(vaultItem);
    }
    console.log("createIntent ", result, rows);


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

  return (
    <ScrollView className="flex-1 bg-black px-4 py-6">
      <Text className="text-2xl font-bold text-white mb-4">Vault</Text>

      <View className="mb-6">
        <Text className="text-white text-lg mb-2">Add item</Text>
        <TextInput
          className="w-full rounded-md bg-white px-3 py-2 mb-2"
          placeholder="Site name"
          placeholderTextColor="#666"
          value={site}
          onChangeText={setSite}
        />
        <TextInput
          className="w-full rounded-md bg-white px-3 py-2 mb-2"
          placeholder="Username"
          placeholderTextColor="#666"
          autoCapitalize="none"
          value={username}
          onChangeText={setUsername}
        />
        <TextInput
          className="w-full rounded-md bg-white px-3 py-2 mb-3"
          placeholder="Password"
          placeholderTextColor="#666"
          secureTextEntry
          value={password}
          onChangeText={setPassword}
        />
        <Pressable
          className="w-full rounded-md bg-blue-600 py-2 items-center"
          onPress={() => {
            if (!site || !username || !password) return;
            console.log("New vault item", { site, username, password });
            handleCreate({ site, username, password });
          }}
        >
          <Text className="text-white">Log values</Text>
        </Pressable>
      </View>

      {!decryptedVault || !decryptedVault.items?.length ? (
        <Text className="text-neutral-400">No items in your vault yet.</Text>
      ) : (
        <View className="space-y-3">
          {decryptedVault.items.map((item, index) => (
            <View
              key={`${item.site}-${item.username}-${index}`}
              className="mb-3 rounded-lg bg-neutral-900 px-4 py-3"
            >
              <Text className="text-lg font-semibold text-white">
                {item.site}
              </Text>
              <Text className="text-sm text-neutral-300 mt-1">
                Username: <Text className="font-medium">{item.username}</Text>
              </Text>
              <Text className="text-sm text-neutral-300 mt-1">
                Password: <Text className="font-medium">{item.password}</Text>
              </Text>
            </View>
          ))}
        </View>
      )}
      
      <Pressable
        className="w-full rounded-md bg-blue-600 py-2 items-center"
        onPress={async () => {
          await sync(queryClient);
        }}
      >
        <Text className="text-white">Sync</Text>
      </Pressable>
    </ScrollView>
  );
}
