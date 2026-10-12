import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  VaultItemSchema,
  UpdateVaultItemSchema,
  OAUTH_IDP_HOSTS,
  normalizeAccount,
  itemHasAccount,
  hasSsoSignIn,
  upsertSsoSignIn,
  ssoProvidersOf,
  providerOfAccountOrigin,
  isProviderOnlySignIn,
  ssoAccountsForProvider,
  ssoItemIdentity,
  findItemForAccount,
  type SsoProvider,
} from "../src/schema.js";
import { uuid } from "../src/crypto.js";

describe("oauth schema", () => {
  it("parses password items (no sso defaults to [])", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      username: "alice",
      password: "pw-1",
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.deepEqual(parsed.data?.sso, []);
  });

  it("parses an SSO-only item: identity in username, method in sso", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      username: "me@gmail.com",
      sso: [{ provider: "google", account: "me@gmail.com" }],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.equal(parsed.data?.password, undefined);
    assert.deepEqual(parsed.data?.sso, [{ provider: "google", account: "me@gmail.com" }]);
  });

  it("parses one account with both a password and an SSO method", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      username: "me@acme.com",
      password: "pw-1",
      sso: [
        { provider: "google", account: "me@acme.com" },
        { provider: "github", account: "octocat" },
      ],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.equal(parsed.data?.password, "pw-1");
    assert.equal(parsed.data?.sso?.length, 2);
  });

  it("rejects unknown providers (quarantine path)", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      username: "me@yahoo.com",
      sso: [{ provider: "yahoo", account: "me@yahoo.com" }],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, false);
  });

  // A method with no account is now a real stored state, not a rejected one:
  // the extension cannot observe the IdP account, so when the vault knows no
  // account for that provider it stores the method alone.
  it("accepts a provider-only method (no account) and keeps it address-less", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      sso: [{ provider: "google", account: "" }],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.deepEqual(parsed.data?.sso, [{ provider: "google", account: "" }]);
    // No identity is invented for it: nothing to match on, nothing to fill.
    assert.equal(parsed.data?.username, undefined);
    assert.equal(parsed.data?.password, undefined);
  });

  it("normalizes a whitespace-only account to provider-only", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      sso: [{ provider: "google", account: "   " }],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.deepEqual(parsed.data?.sso, [{ provider: "google", account: "" }]);
  });

  it("still rejects an over-long account", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      username: "me@gmail.com",
      sso: [{ provider: "google", account: "x".repeat(321) }],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, false);
  });

  it("trims surrounding whitespace off an account", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      username: "me@gmail.com",
      sso: [{ provider: "google", account: "  me@gmail.com  " }],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.equal(parsed.data?.sso?.[0].account, "me@gmail.com");
  });

  it("update carries sso for LWW", () => {
    const parsed = UpdateVaultItemSchema.safeParse({
      id: uuid(),
      fields: { sso: [{ provider: "github", account: "octocat" }] },
    });
    assert.equal(parsed.success, true);
  });

  it("IdP host map covers the four named providers", () => {
    assert.equal(OAUTH_IDP_HOSTS["accounts.google.com"], "google");
    assert.equal(OAUTH_IDP_HOSTS["github.com"], "github");
    assert.equal(OAUTH_IDP_HOSTS["appleid.apple.com"], "apple");
    assert.equal(OAUTH_IDP_HOSTS["login.microsoftonline.com"], "microsoft");
  });
});

describe("account helpers", () => {
  it("compares accounts case-insensitively and ignores surrounding space", () => {
    assert.equal(normalizeAccount("  Me@Gmail.com "), normalizeAccount("me@gmail.com"));
  });

  it("itemHasAccount matches on username regardless of case", () => {
    assert.equal(itemHasAccount({ username: "Me@Gmail.com" }, "me@gmail.com"), true);
    assert.equal(itemHasAccount({ username: "me@gmail.com" }, "ME@GMAIL.COM"), true);
    assert.equal(itemHasAccount({ username: "me@acme.com" }, "me@gmail.com"), false);
  });

  it("hasSsoSignIn matches provider and account together", () => {
    const item = { sso: [{ provider: "google" as const, account: "me@gmail.com" }] };
    assert.equal(hasSsoSignIn(item, "google", "ME@GMAIL.com"), true);
    assert.equal(hasSsoSignIn(item, "github", "me@gmail.com"), false);
    assert.equal(hasSsoSignIn(item, "google", "me@acme.com"), false);
  });

  it("upsertSsoSignIn appends once and is idempotent", () => {
    const first = upsertSsoSignIn([], { provider: "google", account: "me@gmail.com" });
    assert.deepEqual(first, [{ provider: "google", account: "me@gmail.com" }]);
    // Same method re-added (case differs) must not duplicate the row.
    const again = upsertSsoSignIn(first, { provider: "google", account: "ME@GMAIL.COM" });
    assert.equal(again.length, 1);
    // A different account at the same IdP is a genuinely different method.
    const second = upsertSsoSignIn(first, { provider: "google", account: "me@acme.com" });
    assert.equal(second.length, 2);
  });

  it("upsertSsoSignIn does not mutate its input", () => {
    const original = [{ provider: "google" as const, account: "me@gmail.com" }];
    const copy = [...original];
    upsertSsoSignIn(original, { provider: "github", account: "octocat" });
    assert.deepEqual(original, copy);
  });

  it("ssoProvidersOf dedupes providers in first-seen order", () => {
    const item = {
      sso: [
        { provider: "google" as const, account: "me@gmail.com" },
        { provider: "google" as const, account: "me@acme.com" },
        { provider: "github" as const, account: "octocat" },
      ],
    };
    assert.deepEqual(ssoProvidersOf(item), ["google", "github"]);
  });

  // Case F: same origin, two accounts → two items, never merged.
  it("findItemForAccount joins only same-origin + same-account", () => {
    const items = [
      { id: "a", origin: "https://notion.so", username: "me@gmail.com" },
      { id: "b", origin: "https://notion.so", username: "me@acme.com" },
      { id: "c", origin: "https://figma.com", username: "me@gmail.com" },
    ];
    assert.equal(findItemForAccount(items, "https://notion.so", "ME@ACME.com")?.id, "b");
    // Same account, different origin → no match (c is figma, not notion).
    assert.equal(findItemForAccount(items, "https://notion.so", "nobody@new.com"), undefined);
    // Provider-only items have no username, so they never join anything.
    assert.equal(findItemForAccount([{ id: "d", origin: "https://notion.so" }], "https://notion.so", ""), undefined);
  });
});

describe("provider-only sign-ins", () => {
  const items = [
    { sso: [{ provider: "google" as const, account: "me@gmail.com" }] },
    { sso: [{ provider: "google" as const, account: "ME@GMAIL.COM" }] },
    { sso: [{ provider: "google" as const, account: "work@acme.com" }] },
    { sso: [{ provider: "github" as const, account: "octocat" }] },
    { sso: [{ provider: "github" as const, account: "" }] },
  ];

  it("isProviderOnlySignIn treats a blank account as unknown, not absent", () => {
    assert.equal(isProviderOnlySignIn({ provider: "github", account: "" }), true);
    assert.equal(isProviderOnlySignIn({ provider: "github", account: "  " }), true);
    assert.equal(isProviderOnlySignIn({ provider: "google", account: "me@gmail.com" }), false);
  });

  it("ssoAccountsForProvider offers known accounts only, deduped per provider", () => {
    assert.deepEqual(ssoAccountsForProvider(items, "google"), ["me@gmail.com", "work@acme.com"]);
    assert.deepEqual(ssoAccountsForProvider(items, "github"), ["octocat"]);
    assert.deepEqual(ssoAccountsForProvider(items, "apple"), []);
  });

  it("counts a plain password login on the provider's domain as an account", () => {
    // The real case: a `github.com` login storing the handle, with no SSO
    // method anywhere. That handle IS the GitHub account.
    const vault = [
      { username: "lucytang1", password: "pw", origin: "https://github.com", sso: [] },
      { username: "sarang@example.com", password: "pw", origin: "https://us.posthog.com", sso: [] },
    ];
    assert.deepEqual(ssoAccountsForProvider(vault, "github"), ["lucytang1"]);
    assert.deepEqual(ssoAccountsForProvider(vault, "apple"), []);
  });

  it("falls back to the stored site text when an item has no origin", () => {
    // Items captured before origins were recorded must still contribute; free
    // text that isn't a host is ignored rather than guessed at.
    const vault = [
      { username: "lucytang1", site: "github.com" },
      { username: "someone", site: "GitHub (work)" },
    ];
    assert.deepEqual(ssoAccountsForProvider(vault, "github"), ["lucytang1"]);
  });

  it("recognizes provider account domains, including subdomains", () => {
    assert.equal(providerOfAccountOrigin("https://github.com"), "github");
    assert.equal(providerOfAccountOrigin("https://gist.github.com"), "github");
    assert.equal(providerOfAccountOrigin("https://mail.google.com"), "google");
    assert.equal(providerOfAccountOrigin("https://gmail.com"), "google");
    assert.equal(providerOfAccountOrigin("https://outlook.com"), "microsoft");
    // A lookalike or unrelated site is nobody's account domain.
    assert.equal(providerOfAccountOrigin("https://github.com.evil.test"), null);
    assert.equal(providerOfAccountOrigin("https://notgithub.com"), null);
    assert.equal(providerOfAccountOrigin("https://us.posthog.com"), null);
    assert.equal(providerOfAccountOrigin(undefined), null);
  });

  it("offers a Google account from a Gmail login and a method on the same item once", () => {
    const vault = [
      { username: "me@gmail.com", origin: "https://mail.google.com", sso: [{ provider: "google" as const, account: "me@gmail.com" }] },
      { username: "gmail", origin: "https://mail.google.com", sso: [{ provider: "google" as const, account: "" }] },
    ];
    // "gmail" is an identity the vault really holds, so it stays offerable;
    // "me@gmail.com" must appear exactly once despite two sources.
    assert.deepEqual(ssoAccountsForProvider(vault, "google"), ["me@gmail.com", "gmail"]);
  });

  it("hasSsoSignIn matches two provider-only methods as the same method", () => {
    const item = { sso: [{ provider: "github" as const, account: "" }] };
    assert.equal(hasSsoSignIn(item, "github", ""), true);
    assert.equal(hasSsoSignIn(item, "google", ""), false);
  });

  it("ssoItemIdentity names the method when no account is known", () => {
    const label = (p: SsoProvider): string => (p === "google" ? "Google" : "GitHub");
    assert.equal(ssoItemIdentity({ sso: [{ provider: "github", account: "" }] }, label), "Sign in with GitHub");
    assert.equal(
      ssoItemIdentity({ sso: [{ provider: "google", account: "me@gmail.com" }] }, label),
      "me@gmail.com",
    );
    // A stored username always wins — it is the item's real identity.
    assert.equal(
      ssoItemIdentity({ username: "site-user", sso: [{ provider: "google", account: "" }] }, label),
      "site-user",
    );
    assert.equal(ssoItemIdentity({}, label), "");
  });
});