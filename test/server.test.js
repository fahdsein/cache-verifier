import assert from "node:assert/strict";
import { after, test } from "node:test";
import {
  calculateTtl,
  classifyCache,
  discoverAssets,
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
  assert.match(await page.text(), /Cache Verifier/);
});
