import { getClientStateTable } from "@/src/lib/sqlite/web/services/client-state-service"
import { fetchIntents } from "@/src/lib/sqlite/web/services/intent-service"
import { useEffect, useRef, useState } from "react";
import { View } from "react-native";
import { Text } from "react-native";
import { initSQLite } from "@/src/lib/sqlite/web/init-db";
// Debug-only: opens the dev account's database directly. Production code must
// use the session-derived user id (see _layout bootstrap).
const DEV_USER_ID = "00000000-0000-4000-8000-000000000000";

export default function DebugPage() {
  const [clientState, setClientState] = useState<any>([])
  const [intent, setIntent] = useState<any>([])
  // StrictMode double-invokes this effect in development. `initSQLite` closes the
  // current OPFS handle before opening the next, so running it twice concurrently
  // can leave a leaked handle and a stale dbId. The ref survives the simulated
  // remount, so it correctly means "once per mount", not "once ever".
  const opened = useRef(false);
  useEffect(() => {
    if (opened.current) return;
    opened.current = true;
    let active = true;
    const fetchData = async () => {
      await initSQLite(DEV_USER_ID);
      const clientState = await getClientStateTable()
      const intent = await fetchIntents()
      if (!active) return;
      setClientState(clientState)
      setIntent(intent)
    }
    fetchData()
    return () => { active = false; };
  }, [])
  return (
    <View>
      <Text>Debug Page</Text>
      <Text className="text-primary-text">{JSON.stringify(clientState, null, 2)}</Text>
      <Text className="text-primary-text">{JSON.stringify(intent, null, 2)}</Text>
    </View>
  )
}
