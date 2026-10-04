import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  VaultItemSchema,
  UpdateVaultItemSchema,
  OAUTH_IDP_HOSTS,
} from "../src/schema.js";
import { uuid } from "../src/crypto.js";

describe("oauth schema", () => {
  it("parses legacy-style password items (no ssoProviders defaults to [])", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      username: "alice",
      password: "pw-1",
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.deepEqual(parsed.data?.ssoProviders, []);
  });

  it("parses passwordless SSO-only items", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      ssoProviders: ["google"],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.equal(parsed.data?.password, undefined);
    assert.equal(parsed.data?.username, undefined);
  });

  it("parses one item with both password and SSO (multiple sign-in options)", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      username: "alice",
      password: "pw-1",
      ssoProviders: ["google", "github"],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, true);
    assert.deepEqual(parsed.data?.ssoProviders, ["google", "github"]);
  });

  it("rejects unknown providers (quarantine path)", () => {
    const parsed = VaultItemSchema.safeParse({
      id: uuid(),
      site: "example.com",
      ssoProviders: ["yahoo"],
      origin: "https://example.com",
    });
    assert.equal(parsed.success, false);
  });

  it("update carries ssoProviders for LWW", () => {
    const parsed = UpdateVaultItemSchema.safeParse({
      id: uuid(),
      fields: { ssoProviders: ["github"] },
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
