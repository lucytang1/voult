/**
 * Copy for the fixed OAuth callback error codes.
 *
 * The server returns one of a small closed set of `cloud_error` values. The
 * browser must never render a provider-supplied string: it can be attacker-
 * crafted and it is not ours to trust. Unknown values (a newer server, a
 * hand-edited URL) fall back to a generic sentence rather than echoing the
 * input.
 */
const MESSAGES: Record<string, string> = {
  OAUTH_CANCELLED: "Authorization was cancelled or denied.",
  OAUTH_INVALID_REQUEST: "The provider returned an incomplete response. Try again.",
  OAUTH_INVALID_STATE: "This sign-in link expired. Start the connection again.",
  OAUTH_EXCHANGE_FAILED: "The provider could not complete the connection. Try again.",
  OAUTH_UNKNOWN_PROVIDER: "That cloud provider is not supported.",
  OAUTH_PROVIDER_UNCONFIGURED: "Cloud backup is not configured on this server.",
};

export function oauthErrorMessage(raw: string | undefined): string {
  return (raw && MESSAGES[raw]) || "Cloud connection failed. Try again.";
}
