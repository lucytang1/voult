export type SessionResponse = {
  authenticated: boolean;
  vault_id: string;
  crypto_version: number;
  // Global lock signal (POST /api/lock bumps it). The client persists the last
  // epoch it saw and wipes local keys when the server reports a newer one.
  // Absent on old servers — treat as 0.
  lock_epoch?: number;
}
