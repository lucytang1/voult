import { http } from "../http";
import type { PairStartResponse } from "./api.schema";
import { useMutation } from "@tanstack/react-query";

// Mints a one-time extension-pairing code for the session's vault.
// The code is shown once in the UI and redeemable for the vault identity
// only — the extension still requires the master password afterwards.
export async function startExtensionPairing(): Promise<PairStartResponse> {
  const res = await http.post<PairStartResponse>("/pair/start");
  return res.data;
}

export function useStartExtensionPairing() {
  // The one-time code is display-only and should not linger in mutation cache.
  return useMutation({ mutationFn: startExtensionPairing, gcTime: 0 });
}
