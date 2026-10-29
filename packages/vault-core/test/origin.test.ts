import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { canonicalizeOrigin, rankOriginMatch } from "../src/origin.js";

describe("canonicalizeOrigin", () => {
  it("lowercases host and strips default ports", () => {
    assert.equal(canonicalizeOrigin("https://Accounts.EXAMPLE.com:443/a?b=1"), "https://accounts.example.com");
    assert.equal(canonicalizeOrigin("https://example.com"), "https://example.com");
    assert.equal(canonicalizeOrigin("https://example.com:443"), "https://example.com");
  });

  it("keeps non-default ports", () => {
    assert.equal(canonicalizeOrigin("https://example.com:8443/x"), "https://example.com:8443");
    assert.equal(canonicalizeOrigin("https://example.com:80/x"), "https://example.com:80");
  });

  it("treats bare hosts as https", () => {
    assert.equal(canonicalizeOrigin("example.com"), "https://example.com");
  });

  it("strips the DNS root dot so an FQDN matches the stored origin", () => {
    assert.equal(canonicalizeOrigin("https://example.com."), "https://example.com");
    assert.equal(canonicalizeOrigin("https://Example.COM.:8443/x"), "https://example.com:8443");
    // Percent-encoded, repeated, and Unicode dot variants normalize too.
    assert.equal(canonicalizeOrigin("https://example.com%2e"), "https://example.com");
    assert.equal(canonicalizeOrigin("https://example.com../"), "https://example.com");
    assert.equal(canonicalizeOrigin("https://example.com。"), "https://example.com");
    assert.equal(canonicalizeOrigin("https://bücher。de"), "https://xn--bcher-kva.de");
    // An all-dot host has no host left; reject rather than return "https://".
    assert.throws(() => canonicalizeOrigin("https://.."), /empty host/);
  });

  it("drops userinfo instead of treating it as the host", () => {
    assert.equal(canonicalizeOrigin("https://user:pw@example.com/x"), "https://example.com");
    // The host is evil.example, not bank.example — this is the classic
    // "trusted-looking userinfo" URL.
    assert.equal(
      canonicalizeOrigin("https://bank.example@evil.example/x"),
      "https://evil.example",
    );
  });

  it("normalizes IDNs to punycode", () => {
    assert.equal(canonicalizeOrigin("https://bücher.de"), "https://xn--bcher-kva.de");
    assert.equal(canonicalizeOrigin("https://XN--BCHER-KVA.DE"), "https://xn--bcher-kva.de");
    assert.equal(canonicalizeOrigin("https://bücher.de./x"), "https://xn--bcher-kva.de");
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
    assert.equal(canonicalizeOrigin("http://localhost./x"), "http://localhost");
    assert.equal(canonicalizeOrigin("http://127.0.0.1/"), "http://127.0.0.1");
    assert.equal(canonicalizeOrigin("http://[::1]:8080/"), "http://[::1]:8080");
    assert.equal(canonicalizeOrigin("http://app.localhost/"), "http://app.localhost");
  });

  it("rejects unparseable input", () => {
    assert.throws(() => canonicalizeOrigin(""), Error);
    assert.throws(() => canonicalizeOrigin("https://"), Error);
    assert.throws(() => canonicalizeOrigin("not a url at all@@"), Error);
  });
});

describe("rankOriginMatch", () => {
  it("exact origin wins over everything", () => {
    assert.deepEqual(
      rankOriginMatch({ origin: "https://a.example.com" }, "https://a.example.com/login"),
      { kind: "exact" },
    );
  });

  it("exact match ignores path, query, default port, and page userinfo", () => {
    assert.deepEqual(
      rankOriginMatch({ origin: "https://example.com" }, "https://example.com:443/x?y=1"),
      { kind: "exact" },
    );
    assert.deepEqual(
      rankOriginMatch({ origin: "https://example.com" }, "https://user:pw@example.com/x"),
      { kind: "exact" },
    );
    assert.deepEqual(
      rankOriginMatch({ origin: "https://example.com." }, "https://example.com/x"),
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

  it("does not infer a relation between sibling subdomains", () => {
    // The old last-two-labels fallback matched these. It is the exact class
    // of origin confusion the fallback was removed for.
    assert.equal(
      rankOriginMatch({ origin: "https://login.example.com" }, "https://app.example.com/"),
      null,
    );
    assert.equal(
      rankOriginMatch({ origin: "https://example.com" }, "https://www.example.com/"),
      null,
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
