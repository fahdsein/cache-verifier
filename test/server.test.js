import assert from "node:assert/strict";
import { after, test } from "node:test";
import {
  analyzePair,
  calculateTtl,
  classifyCache,
  detectVarnish,
  discoverAssets,
  estimateCacheTime,
  isPrivateAddress,
  startServer
} from "../server.js";

test("blocks private and local addresses", () => {
  for (const address of ["127.0.0.1", "10.2.3.4", "172.20.1.2", "192.168.1.9", "169.254.4.2", "::1", "fd00::1", "fe80::1"]) {
    assert.equal(isPrivateAddress(address), true, address);
  }
  for (const address of ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]) {
    assert.equal(isPrivateAddress(address), false, address);
  }
});

test("classifies common CDN headers", () => {
  assert.equal(classifyCache({ "cf-cache-status": "HIT" }), "HIT");
  assert.equal(classifyCache({ "x-cache": "Miss from cloudfront" }), "MISS");
  assert.equal(classifyCache({ age: "28" }), "HIT (inferred)");
  assert.equal(classifyCache({}), "UNKNOWN");
});

test("calculates remaining cache TTL", () => {
  assert.deepEqual(calculateTtl({ "cache-control": "public, max-age=3600", age: "120" }), {
    ageSeconds: 120,
    maxAgeSeconds: 3600,
    remainingSeconds: 3480
  });
});

test("separates explicit Varnish delivery signals from recency", () => {
  assert.deepEqual(detectVarnish({
    server: "Varnish",
    via: "1.1 varnish",
    "x-varnish": "654321 123456",
    "x-cache": "hit graced"
  }), {
    detected: true,
    delivery: "GRACE",
    confidence: "high",
    evidence: "X-Cache reports a graced hit.",
    transactionIds: ["654321", "123456"]
  });

  const inferred = detectVarnish({ "x-varnish": "654321 123456" });
  assert.equal(inferred.delivery, "LIKELY HIT");
  assert.equal(inferred.confidence, "low");
});

test("estimates cache time from Date minus Age", () => {
  assert.equal(
    estimateCacheTime({ date: "Fri, 10 Oct 2026 10:00:00 GMT", age: "3600" }),
    "2026-10-10T09:00:00.000Z"
  );
  assert.equal(estimateCacheTime({ date: "Fri, 10 Oct 2026 10:00:00 GMT" }), null);
});

test("flags a cached Varnish object that predates a known update", () => {
  const normal = {
    ok: true,
    status: 200,
    text: "old page",
    hash: "same",
    truncated: false,
    headers: {
      date: "Fri, 10 Oct 2026 10:00:00 GMT",
      age: "3600",
      server: "Varnish",
      "x-varnish": "654321 123456",
      "x-cache": "hit cached"
    }
  };
  const bypass = { ...normal, headers: { ...normal.headers, age: "0" } };
  const result = analyzePair(normal, bypass, "", "varnish", "2026-10-10T09:30:00.000Z");
  assert.equal(result.verdict, "possible-stale");
  assert.equal(result.confidence, "medium");
  assert.equal(result.delivery, "HIT");
  assert.equal(result.estimatedCachedAt, "2026-10-10T09:00:00.000Z");
});

test("expected newest-content marker overrides cache age heuristics", () => {
  const response = {
    ok: true,
    status: 200,
    text: "new release marker",
    hash: "same",
    truncated: false,
    headers: {
      date: "Fri, 10 Oct 2026 10:00:00 GMT",
      age: "7200",
      via: "1.1 varnish",
      "x-cache": "hit cached"
    }
  };
  const result = analyzePair(response, response, "new release marker", "varnish", "2026-10-10T09:30:00.000Z");
  assert.equal(result.verdict, "current");
  assert.equal(result.confidence, "high");
});

test("discovers deduplicated public asset references", () => {
  const html = '<link href="/app.css"><script src="/app.js"></script><img src="/photo.webp"><a href="/about">About</a><script src="/app.js"></script>';
  assert.deepEqual(discoverAssets(html, "https://example.com/page"), [
    "https://example.com/app.css",
    "https://example.com/app.js",
    "https://example.com/photo.webp"
  ]);
});

const server = startServer(0);
after(() => new Promise((resolve) => server.close(resolve)));

test("serves health and UI endpoints", async () => {
  await new Promise((resolve) => server.listening ? resolve() : server.once("listening", resolve));
  const port = server.address().port;
  const health = await fetch("http://127.0.0.1:" + port + "/healthz");
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ok", service: "cache-verifier" });

  const page = await fetch("http://127.0.0.1:" + port + "/");
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Environment Cache Comparator/);

  const meta = await fetch("http://127.0.0.1:" + port + "/api/meta");
  assert.equal(meta.status, 200);
  const metadata = await meta.json();
  assert.equal(metadata.version, "2.0.0");
  assert.ok(metadata.features.includes("environment-comparison"));
});
