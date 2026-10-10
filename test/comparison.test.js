import assert from "node:assert/strict";
import { test } from "node:test";
import {
  compareEnvironmentSnapshots,
  extractReleaseInfo,
  isBlockedAddress,
  normalizeHtmlContent,
  normalizeRuntimeOptions,
  shouldBypassEnvironment
} from "../comparison.js";

function snapshot(environment, overrides = {}) {
  return {
    environment,
    verdict: "consistent",
    contentType: "text/html; charset=utf-8",
    hash: overrides.hash || "hash-a",
    normalizedHash: overrides.normalizedHash || overrides.hash || "hash-a",
    expectedTextFound: overrides.expectedTextFound ?? null,
    release: { releaseId: overrides.releaseId || "", builtAt: "", source: "" },
    ...overrides
  };
}

test("forced-IP protection blocks private and reserved ranges", () => {
  for (const address of ["127.0.0.1", "10.0.0.2", "172.16.0.2", "192.168.2.2", "169.254.1.2", "192.0.2.10", "198.51.100.20", "203.0.113.30", "::1", "fd00::1", "2001:db8::1"]) {
    assert.equal(isBlockedAddress(address), true, address);
  }
  assert.equal(isBlockedAddress("1.1.1.1"), false);
  assert.equal(isBlockedAddress("2606:4700:4700::1111"), false);
});

test("extracts release identity from headers, JSON, and HTML metadata", () => {
  assert.deepEqual(extractReleaseInfo("", "text/plain", { "x-release-id": "release-12" }), {
    releaseId: "release-12",
    builtAt: "",
    source: "response header x-release-id"
  });
  assert.deepEqual(extractReleaseInfo('{"releaseId":"release-13","builtAt":"2026-10-10T10:00:00Z"}', "application/json"), {
    releaseId: "release-13",
    builtAt: "2026-10-10T10:00:00Z",
    source: "JSON document"
  });
  assert.deepEqual(extractReleaseInfo('<meta name="release-id" content="release-14"><meta content="2026-10-10T10:00:00Z" name="built-at">', "text/html"), {
    releaseId: "release-14",
    builtAt: "2026-10-10T10:00:00Z",
    source: "HTML meta tag"
  });
});

test("normalizes environment origins and volatile HTML attributes", () => {
  const first = normalizeHtmlContent('<html><!-- note --><script nonce="abc" data-request-id="one" src="https://staging.example/app.js"></script></html>', "https://staging.example");
  const second = normalizeHtmlContent('<html><script nonce="xyz" data-request-id="two" src="https://www.example/app.js"></script></html>', "https://www.example");
  assert.equal(first, second);
});

test("identifies a CDN stale condition from expected release IDs", () => {
  const result = compareEnvironmentSnapshots([
    snapshot("staging", { releaseId: "new" }),
    snapshot("productionCdn", { releaseId: "old" }),
    snapshot("productionHost", { releaseId: "new" })
  ], { expectedText: "" }, { expectedReleaseId: "new", normalizeHtml: true });
  assert.equal(result.code, "cdn-stale");
  assert.equal(result.confidence, "high");
});

test("identifies deployment lag before blaming the CDN", () => {
  const result = compareEnvironmentSnapshots([
    snapshot("staging", { releaseId: "new" }),
    snapshot("productionCdn", { releaseId: "old" }),
    snapshot("productionHost", { releaseId: "old" })
  ], { expectedText: "" }, { expectedReleaseId: "new", normalizeHtml: true });
  assert.equal(result.code, "not-deployed");
});

test("uses normalized hashes when no release marker exists", () => {
  const result = compareEnvironmentSnapshots([
    snapshot("staging", { normalizedHash: "new" }),
    snapshot("productionCdn", { normalizedHash: "old" }),
    snapshot("productionHost", { normalizedHash: "new" })
  ], { expectedText: "" }, { expectedReleaseId: "", normalizeHtml: true });
  assert.equal(result.code, "cdn-stale");
  assert.equal(result.confidence, "medium");
});

test("uses safe runtime defaults and clamps user-controlled limits", () => {
  assert.deepEqual(normalizeRuntimeOptions({}), {
    comparisonMode: "quick",
    timeoutMs: 8000,
    retryCount: 1,
    targetConcurrency: 2,
    batchDeadlineMs: 40000,
    assetDiscoveryLimit: 3
  });
  assert.deepEqual(normalizeRuntimeOptions({
    comparisonMode: "deep",
    timeoutMs: 99999,
    retryCount: 9,
    targetConcurrency: 12,
    batchDeadlineMs: 99999,
    assetDiscoveryLimit: 99
  }), {
    comparisonMode: "deep",
    timeoutMs: 15000,
    retryCount: 1,
    targetConcurrency: 3,
    batchDeadlineMs: 45000,
    assetDiscoveryLimit: 10
  });
});

test("quick mode bypasses only the public production CDN", () => {
  assert.equal(shouldBypassEnvironment("staging", "quick"), false);
  assert.equal(shouldBypassEnvironment("productionHost", "quick"), false);
  assert.equal(shouldBypassEnvironment("productionCdn", "quick"), true);
  assert.equal(shouldBypassEnvironment("staging", "deep"), true);
});
