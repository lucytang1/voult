import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { canonicalizeOrigin, rankOriginMatch } from "../src/origin.js";

describe("canonicalizeOrigin", () => {
  it("lowercases host and strips default ports", () => {
    assert.equal(canonicalizeOrigin("https://Accounts.EXAMPLE.com:443/a?b=1"), "https://accounts.example.com");
    assert.equal(canonicalizeOrigin("https://example.com"), "https://example.com");
  });

  it("keeps non-default ports", () => {
    assert.equal(canonicalizeOrigin("https://example.com:8443/x"), "https://example.com:8443");
  });

  it("treats bare hosts as https", () => {
    assert.equal(canonicalizeOrigin("example.com"), "https://example.com");
  });

  it("rejects non-http(s) schemes", () => {
    assert.throws(() => canonicalizeOrigin("ftp://example.com"), /Unsupported scheme/);
    // javascript: URLs never match http(s) — rejected either as a bad scheme
    // or an unparseable URL. Either way nothing is ever matched or stored.
    assert.throws(() => canonicalizeOrigin("javascript:alert(1)"), Error);
  });

  it("rejects non-loopback http, allows loopback http", () => {
    assert.throws(() => canonicalizeOrigin("http://example.com"), /non-loopback/);
    assert.equal(canonicalizeOrigin("http://localhost:8080/x"), "http://localhost:8080");
    assert.equal(canonicalizeOrigin("http://127.0.0.1/"), "http://127.0.0.1");
  });
});

describe("rankOriginMatch", () => {
  it("exact origin wins over everything", () => {
    assert.deepEqual(
      rankOriginMatch({ origin: "https://a.example.com" }, "https://a.example.com/login"),
      { kind: "exact" },
    );
  });

  it("matches explicitly linked urls", () => {
    assert.deepEqual(
      rankOriginMatch(
        { origin: "https://a.example.com", urls: ["https://b.example.com"] },
        "https://b.example.com/",
      ),
      { kind: "linked" },
    );
  });

  it("falls back to same-suffix subdomain, marked weaker", () => {
    assert.deepEqual(
      rankOriginMatch({ origin: "https://login.example.com" }, "https://app.example.com/"),
      { kind: "subdomain" },
    );
  });

  it("never matches across origins or schemes", () => {
    assert.equal(rankOriginMatch({ origin: "https://example.com" }, "https://examp1e.com/"), null);
    assert.equal(rankOriginMatch({ origin: "https://example.com" }, "https://other.com/"), null);
    assert.equal(rankOriginMatch({ origin: "https://example.com" }, "not a url at all@@"), null);
  });

  it("items without origin never match", () => {
    assert.equal(rankOriginMatch({}, "https://example.com/"), null);
  });
});
