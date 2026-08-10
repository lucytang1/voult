import { useEffect } from "react";
import { syncScheduler } from "./sync-scheduler";

export function useSyncTriggers() {
  useEffect(() => {
    if (typeof window === "undefined") return;
    const onFocus = () => syncScheduler.requestSync("window-focus");
    const onOnline = () => syncScheduler.requestSync("network-reconnect");
    window.addEventListener("focus", onFocus);
    window.addEventListener("online", onOnline);
    return () => {
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("online", onOnline);
    };
  }, []);
}
