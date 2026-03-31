import { getClientStateTable } from "@/src/lib/sqlite/web/services/client-state-service"
import { fetchIntents } from "@/src/lib/sqlite/web/services/intent-service"
import { useEffect, useState } from "react";
import { View } from "react-native";
import { Text } from "react-native";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";

export default function DebugPage() {
  const [clientState, setClientState] = useState<any>([])
  const [intent, setIntent] = useState<any>([])
  useEffect(() => {
    const fetchData = async () => {
      await initSQLite();
      const clientState = await getClientStateTable()
      const intent = await fetchIntents()
      setClientState(clientState)
      setIntent(intent)
    }
    fetchData()
  }, [])
  return (
    <View>
      <Text>Debug Page</Text>
      <Text className="text-white">{JSON.stringify(clientState, null, 2)}</Text>
      <Text className="text-white">{JSON.stringify(intent, null, 2)}</Text>
    </View>
  )
}
