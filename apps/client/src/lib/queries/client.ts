import { QueryClient } from "@tanstack/react-query";

// One process-wide cache lets the HTTP session-expiry interceptor clear the
// same query state rendered by the app. The cache is in-memory only.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
    // Mutation variables may contain passwords, pairing codes, or encrypted
    // payloads. Drop completed command state as soon as observers release it.
    mutations: { gcTime: 0 },
  },
});
