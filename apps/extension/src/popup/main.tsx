import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Popup } from "./Popup";

const el = document.getElementById("root");
if (!el) throw new Error("Voult popup: #root missing");
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, staleTime: 0, gcTime: 0, refetchOnWindowFocus: false },
    mutations: { gcTime: 0 },
  },
});

createRoot(el).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Popup />
    </QueryClientProvider>
  </StrictMode>,
);
