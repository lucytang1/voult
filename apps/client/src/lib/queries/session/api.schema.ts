export type SessionResponse = {
  authenticated: boolean;
  user: {
    id: string;
    email: string;
  };
  crypto_version: number;
}
