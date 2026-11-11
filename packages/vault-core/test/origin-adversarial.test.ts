// Adversarial origin matrix for the extension's login matching.
//
// Policy: an item matches only by exact canonical origin or by an explicitly
// linked `urls` entry. There is no subdomain/suffix fallback. These tests pin
// the cases that the removed last-two-labels fallback used to confuse,
// including the roadmap's `co.uk`/`github.io` examples, ports, schemes, IDNs,
// userinfo, and trailing dots.
//
// `decideFillBest` is tested here too: a weak rank must never become an
// automatic fill, even if a future rank is introduced.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  decideFillBest,
  rankOriginMatch,
} from "../src/origin.js";

describe("rankOriginMatch adversarial matrix", () => {
  it("keeps exact matches working (positive controls)", () => {
    const exact = [
      ["https://a.example.com", "https://a.example.com/login?x=1"],
      ["https://example.com:8443", "https://example.com:8443/x"],
      ["https://bücher.de", "https://bücher.de/login"],
      ["https://xn--bcher-kva.de", "https://bücher.de/login"],
      ["https://example.com.", "https://example.com/"],
      ["https://example.com", "https://user:pw@example.com/"],
      ["https://example.com", "https://example.com:443/x"],
    ] as const;
    for (const [item, page] of exact) {
      assert.deepEqual(rankOriginMatch({ origin: item }, page), { kind: "exact" }, `${item} on ${page}`);
    }
  });

  it("keeps explicitly linked urls working (positive control)", () => {
    assert.deepEqual(
      rankOriginMatch(
        { origin: "https://a.example.com", urls: ["https://b.example.com/login"] },
        "https://b.example.com/x",
      ),
      { kind: "linked" },
    );
  });

  it("never relates sites that only share a multi-label public suffix", () => {
    const pairs = [
      ["https://bank.co.uk", "https://other.co.uk"],
      ["https://alice.github.io", "https://mallory.github.io"],
      // A stored public-suffix apex must not become a wildcard for its tenants.
      ["https://github.io", "https://mallory.github.io"],
      ["https://github.com", "https://gist.github.com"],
      // Platforms that host tenants under their own registrable apex are the
      // reason a PSL does not fully solve this class either.
      ["https://wordpress.com", "https://evil.wordpress.com"],
      ["https://tumblr.com", "https://evil.tumblr.com"],
    ] as const;
    for (const [item, page] of pairs) {
      assert.equal(rankOriginMatch({ origin: item }, page), null, `${item} on ${page}`);
    }
  });

  it("never relates sibling or parent/child hosts", () => {
    const pairs = [
      ["https://login.example.com", "https://app.example.com"],
      ["https://example.com", "https://www.example.com"],
      ["https://www.example.com", "https://example.com"],
      ["https://example.com", "https://example.com.evil.com"],
      ["https://example.com", "https://notexample.com"],
      ["https://example.com", "https://examp1e.com"],
      ["https://bank.com.", "https://evil.com."],
    ] as const;
    for (const [item, page] of pairs) {
      assert.equal(rankOriginMatch({ origin: item }, page), null, `${item} on ${page}`);
    }
  });

  it("treats a different port or scheme as a different site", () => {
    const pairs = [
      ["https://example.com:8443", "https://example.com:9000"],
      ["https://example.com:8443", "https://example.com"],
      ["http://localhost:8080", "https://localhost:8080"],
      ["http://localhost:8080", "http://localhost:3000"],
    ] as const;
    for (const [item, page] of pairs) {
      assert.equal(rankOriginMatch({ origin: item }, page), null, `${item} on ${page}`);
    }
  });

  it("never derives a relation from IP literals or single-label hosts", () => {
    const pairs = [
      ["https://127.0.0.1", "https://10.0.0.1"],
      ["https://localhost", "https://app.localhost"],
      ["https://com", "https://example.com"],
    ] as const;
    for (const [item, page] of pairs) {
      assert.equal(rankOriginMatch({ origin: item }, page), null, `${item} on ${page}`);
    }
  });

  it("treats an IDN confusable as a different origin", () => {
    // U+0430 CYRILLIC SMALL LETTER A, not ASCII "a".
    assert.equal(
      rankOriginMatch({ origin: "https://apple.com" }, "https://аpple.com/"),
      null,
    );
  });

  it("is not fooled by userinfo, non-http(s), or unparseable pages", () => {
    assert.equal(
      rankOriginMatch(
        { origin: "https://bank.co.uk" },
        "https://bank.co.uk@evil.co.uk/",
      ),
      null,
    );
    assert.equal(rankOriginMatch({ origin: "https://example.com" }, "chrome-extension://abc/"), null);
    assert.equal(rankOriginMatch({ origin: "https://example.com" }, "not a url"), null);
    assert.equal(rankOriginMatch({}, "https://example.com/"), null);
  });
});

describe("decideFillBest invariant", () => {
  it("fills exactly one strong match", () => {
    assert.deepEqual(decideFillBest([{ id: "a", rank: "exact" }]), {
      kind: "fill",
      match: { id: "a", rank: "exact" },
    });
    assert.deepEqual(decideFillBest([{ id: "a", rank: "linked" }]), {
      kind: "fill",
      match: { id: "a", rank: "linked" },
    });
  });

  it("never auto-fills a weaker rank", () => {
    // Synthetic: the ranker no longer produces "subdomain", but the helper
    // must stay fail-closed if a future rank is added without updating it.
    assert.deepEqual(decideFillBest([{ id: "a", rank: "subdomain" }]), {
      kind: "choose",
    });
  });

  it("fills the exact match beside a weaker one", () => {
    assert.deepEqual(
      decideFillBest([
        { id: "a", rank: "exact" },
        { id: "b", rank: "subdomain" },
      ]),
      { kind: "fill", match: { id: "a", rank: "exact" } },
    );
  });

  it("asks the user when several strong matches exist", () => {
    assert.deepEqual(
      decideFillBest([
        { id: "a", rank: "exact" },
        { id: "b", rank: "linked" },
      ]),
      { kind: "choose" },
    );
  });

  it("does nothing when there are no matches", () => {
    assert.deepEqual(decideFillBest([]), { kind: "none" });
  });
});
