import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Slot } from "expo-router";
import "../../global.css";
import { initSQLite } from "../lib/sqlite/web/init-db";
import { useSyncTriggers } from "../lib/sync/use-sync-triggers";
import { useEffect } from "react";
const queryClient = new QueryClient();

export default function RootLayout() {
  // useSyncTriggers();
  useEffect(() => {
    const fetchData = async () => {
      await initSQLite();
    }
    fetchData();
  }, []);
  return (
    // <PostHogProvider apiKey="phc_hPhzKttZrCe9Mv8wYiXdCYq7nQsl6LypkOK2853BnnK" options={{
    //   host: 'https://prp.lucytang.dev',
    //   customStorage: AsyncStorage
    // }}>
    // {/* </PostHogProvider> */}
    <QueryClientProvider client={queryClient}>
      <Slot />
    </QueryClientProvider>
  );
}
