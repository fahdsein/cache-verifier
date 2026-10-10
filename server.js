import { createHash, randomUUID } from "node:crypto";
import dns from "node:dns/promises";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runComparison } from "./comparison.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(ROOT, "public");
const MAX_BODY_BYTES = 64 * 1024;
const MAX_REMOTE_BYTES = 4 * 1024 * 1024;
const MAX_TARGETS = 20;
const MAX_DISCOVERED_ASSETS = 10;
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 5;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_REQUESTS = 30;
const MAX_BATCH_TARGETS = 3;
const rateLimits = new Map();

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml"
};

const OBSERVED_HEADERS = [
  "age",
  "cache-control",
  "cdn-cache-control",
  "cf-cache-status",
  "cf-ray",
  "date",
  "etag",
  "expires",
  "last-modified",
  "server",
  "surrogate-control",
  "via",
  "warning",
  "x-cache",
  "x-cacheable",
  "x-cache-hits",
  "x-cdn",
  "x-served-by",
  "x-varnish",
  "x-vercel-cache"
];

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(body);
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body is too large");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw new Error("Request body must be valid JSON");
  }
}

function parseIpv4(address) {
  const parts = address.split(".").map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? parts
    : null;
}

export function isPrivateAddress(address) {
  const normalized = address.toLowerCase().split("%")[0];
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateAddress(mapped[1]);

  if (net.isIPv4(normalized)) {
    const [a, b] = parseIpv4(normalized);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }

  if (net.isIPv6(normalized)) {
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      /^fe[89ab]/.test(normalized)
    );
  }

  return true;
}

export async function validateRemoteUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Invalid URL");
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS URLs are allowed");
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed");
  if (url.hostname.toLowerCase() === "localhost") throw new Error("Local and private network targets are not allowed");

  const addresses = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error("Local and private network targets are not allowed");
  }
  return url;
}

function headersToObject(headers) {
  const output = {};
  for (const name of OBSERVED_HEADERS) {
    const value = headers.get(name);
    if (value) output[name] = value;
  }
  return output;
}

export function classifyCache(headers) {
  const signal = [
    headers["cf-cache-status"],
    headers["x-vercel-cache"],
    headers["x-cache"],
    headers["x-cache-hits"],
    headers["cdn-cache-control"]
  ].filter(Boolean).join(" ").toUpperCase();

  for (const state of ["GRACE", "STALE", "REVALIDATED", "EXPIRED", "BYPASS", "PASS", "PIPE", "DYNAMIC", "MISS", "HIT"]) {
    if (signal.includes(state)) return state;
  }
  return Number(headers.age || 0) > 0 ? "HIT (inferred)" : "UNKNOWN";
}

export function calculateTtl(headers) {
  const cacheControl = [headers["cdn-cache-control"], headers["cache-control"]].filter(Boolean).join(",");
  const match = cacheControl.match(/(?:s-maxage|max-age)\s*=\s*(\d+)/i);
  const maxAge = match ? Number(match[1]) : null;
  const age = Number.parseInt(headers.age || "0", 10);
  return {
    ageSeconds: Number.isFinite(age) ? age : 0,
    maxAgeSeconds: maxAge,
    remainingSeconds: maxAge === null ? null : Math.max(0, maxAge - (Number.isFinite(age) ? age : 0))
  };
}

export function detectVarnish(headers) {
  const via = String(headers.via || "");
  const server = String(headers.server || "");
  const xVarnish = String(headers["x-varnish"] || "").trim();
  const xCache = String(headers["x-cache"] || "").trim();
  const detected = Boolean(xVarnish || /varnish/i.test(via) || /varnish/i.test(server));
  const transactionIds = (xVarnish.match(/\d+/g) || []).slice(0, 8);
  const cacheSignal = xCache.toLowerCase();
  let delivery = "UNKNOWN";
  let confidence = "none";
  let evidence = detected ? "Varnish signature found, but no explicit delivery result was exposed." : "No Varnish signature was exposed.";

  if (/hit\s+graced|grace/.test(cacheSignal)) {
    delivery = "GRACE";
    confidence = "high";
    evidence = "X-Cache reports a graced hit.";
  } else if (/\bhit\b/.test(cacheSignal)) {
    delivery = "HIT";
    confidence = "high";
    evidence = "X-Cache explicitly reports a cache hit.";
  } else if (/\bmiss\b/.test(cacheSignal)) {
    delivery = "MISS";
    confidence = "high";
    evidence = "X-Cache explicitly reports a cache miss.";
  } else if (/\bpass\b/.test(cacheSignal)) {
    delivery = "PASS";
    confidence = "high";
    evidence = "X-Cache explicitly reports a cache pass.";
  } else if (/\bpipe\b/.test(cacheSignal)) {
    delivery = "PIPE";
    confidence = "high";
    evidence = "X-Cache explicitly reports a piped request.";
  } else if (detected && transactionIds.length >= 2) {
    delivery = "LIKELY HIT";
    confidence = "low";
    evidence = "X-Varnish contains multiple transaction IDs. This is a convention, not a guaranteed modern Varnish rule.";
  } else if (detected && transactionIds.length === 1) {
    delivery = "LIKELY MISS";
    confidence = "low";
    evidence = "X-Varnish contains one transaction ID. This is a convention, not definitive proof of a miss.";
  } else if (detected && Number(headers.age || 0) > 0) {
    delivery = "LIKELY HIT";
    confidence = "low";
    evidence = "A positive Age value suggests cached delivery, but it does not prove content staleness.";
  }

  return {
    detected,
    delivery,
    confidence,
    evidence,
    transactionIds
  };
}

export function estimateCacheTime(headers) {
  if (!headers.date || headers.age === undefined) return null;
  const responseTime = Date.parse(headers.date);
  const ageSeconds = Number(headers.age);
  if (!Number.isFinite(responseTime) || !Number.isFinite(ageSeconds) || ageSeconds < 0) return null;
  return new Date(responseTime - ageSeconds * 1000).toISOString();
}

async function readRemoteBody(response) {
  if (!response.body) return { buffer: Buffer.alloc(0), truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > MAX_REMOTE_BYTES) {
      const remaining = Math.max(0, MAX_REMOTE_BYTES - size);
      if (remaining) chunks.push(Buffer.from(value.subarray(0, remaining)));
      size += remaining;
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(Buffer.from(value));
    size += value.byteLength;
  }
  return { buffer: Buffer.concat(chunks), truncated };
}

async function fetchWithValidatedRedirects(initialUrl, { bypass = false } = {}) {
  let current = new URL(initialUrl);
  if (bypass) {
    current.searchParams.set("__cache_verifier", Date.now() + "-" + randomUUID().slice(0, 8));
  }

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    await validateRemoteUrl(current.href);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const startedAt = performance.now();
    let response;
    try {
      response = await fetch(current, {
        redirect: "manual",
        signal: controller.signal,
        headers: {
          Accept: "*/*",
          "User-Agent": "CacheVerifier/1.0 (+server-side diagnostic)",
          ...(bypass ? { "Cache-Control": "no-cache", Pragma: "no-cache" } : {})
        }
      });
    } finally {
      clearTimeout(timer);
    }
    const latencyMs = Math.round(performance.now() - startedAt);

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) throw new Error("Redirect response did not include a Location header");
      if (redirects === MAX_REDIRECTS) throw new Error("Too many redirects");
      current = new URL(location, current);
      continue;
    }

    const { buffer, truncated } = await readRemoteBody(response);
    const contentType = response.headers.get("content-type") || "";
    const isText = /(?:text\/|json|javascript|xml|svg)/i.test(contentType);
    return {
      requestedUrl: initialUrl,
      finalUrl: current.href,
      status: response.status,
      ok: response.ok,
      latencyMs,
      contentType,
      sizeBytes: buffer.byteLength,
      truncated,
      hash: createHash("sha256").update(buffer).digest("hex"),
      text: isText ? buffer.toString("utf8") : "",
      headers: headersToObject(response.headers)
    };
  }
  throw new Error("Too many redirects");
}

export function discoverAssets(html, pageUrl, limit = MAX_DISCOVERED_ASSETS) {
  const assets = [];
  const seen = new Set();
  const pattern = /(?:src|href)\s*=\s*["']([^"'#]+)["']/gi;
  let match;
  while ((match = pattern.exec(html)) && assets.length < limit) {
    try {
      const url = new URL(match[1], pageUrl);
      if (!["http:", "https:"].includes(url.protocol)) continue;
      if (seen.has(url.href)) continue;
      if (!/\.(?:css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf)(?:\?|$)/i.test(url.pathname + url.search)) continue;
      seen.add(url.href);
      assets.push(url.href);
    } catch {
      // Ignore malformed asset references.
    }
  }
  return assets;
}

export function analyzePair(normal, bypass, expectedText, expectedEdge, contentUpdatedAt) {
  const cacheState = classifyCache(normal.headers);
  const ttl = calculateTtl(normal.headers);
  const varnish = detectVarnish(normal.headers);
  const delivery = varnish.detected && varnish.delivery !== "UNKNOWN" ? varnish.delivery : cacheState;
  const estimatedCachedAt = estimateCacheTime(normal.headers);
  const normalContains = expectedText ? normal.text.includes(expectedText) : null;
  const bypassContains = expectedText ? bypass.text.includes(expectedText) : null;
  const sameContent = normal.hash === bypass.hash;
  const edgeValues = [
    normal.headers.via,
    normal.headers.server,
    normal.headers["x-cache"],
    normal.headers["x-varnish"],
    normal.headers["cf-ray"],
    normal.headers["x-served-by"]
  ].filter(Boolean).join(" ");
  const edgeMatched = expectedEdge ? edgeValues.toLowerCase().includes(expectedEdge.toLowerCase()) : null;

  let verdict = "consistent";
  let confidence = "low";
  let rationale = "The regular and cache-bypassed probes returned the same content hash.";
  if (!normal.ok) {
    verdict = "error";
    confidence = "high";
    rationale = "The target returned HTTP " + normal.status + ".";
  } else if (!bypass.ok) {
    verdict = "unverifiable";
    confidence = "low";
    rationale = "The regular response succeeded, but the cache-bypassed probe returned HTTP " + bypass.status + ". The URL may be signed or reject query parameters.";
  } else if (expectedText && normalContains) {
    verdict = "current";
    confidence = "high";
    rationale = "The regular response contains the expected newest-content marker.";
  } else if (expectedText && !normalContains && bypassContains) {
    verdict = "stale";
    confidence = "high";
    rationale = "The marker is missing from the regular response but present in the cache-bypassed response.";
  } else if (expectedText && !normalContains && !bypassContains) {
    verdict = "marker-missing";
    confidence = "medium";
    rationale = "The expected marker is missing from both probes; confirm the new content is deployed.";
  } else if (contentUpdatedAt && estimatedCachedAt && Date.parse(estimatedCachedAt) < Date.parse(contentUpdatedAt) && /HIT|GRACE/.test(delivery)) {
    verdict = "possible-stale";
    confidence = "medium";
    rationale = "The estimated cached-object time predates the supplied content-update time and the response appears to be a cache hit.";
  } else if (contentUpdatedAt && estimatedCachedAt && Date.parse(estimatedCachedAt) >= Date.parse(contentUpdatedAt)) {
    verdict = "likely-current";
    confidence = "medium";
    rationale = "The estimated cached-object time is at or after the supplied content-update time.";
  } else if (delivery === "GRACE") {
    verdict = "grace";
    confidence = "medium";
    rationale = "Varnish appears to be serving an expired object within its grace period while refresh may occur in the background.";
  } else if (!sameContent) {
    verdict = "different";
    confidence = "low";
    rationale = "Regular and cache-bypassed content differs. This can indicate stale cache or a dynamic page.";
  } else if (normal.truncated || bypass.truncated) {
    verdict = "limited";
    confidence = "low";
    rationale = "The response exceeded 4 MiB; the comparison covers only the captured prefix.";
  } else if (cacheState === "UNKNOWN") {
    verdict = "unverifiable";
    confidence = "low";
    rationale = "Content is consistent, but no recognized CDN cache header was exposed.";
  }

  return {
    cacheState,
    delivery,
    ttl,
    varnish,
    estimatedCachedAt,
    contentUpdatedAt: contentUpdatedAt || "",
    sameContent,
    expectedText: expectedText || "",
    expectedTextFound: normalContains,
    bypassExpectedTextFound: bypassContains,
    expectedEdge: expectedEdge || "",
    edgeMatched,
    verdict,
    confidence,
    rationale
  };
}

async function inspectTarget(target, expectedEdge, contentUpdatedAt, kind = "page") {
  const normal = await fetchWithValidatedRedirects(target.url);
  const bypass = await fetchWithValidatedRedirects(target.url, { bypass: true });
  return {
    kind,
    url: target.url,
    finalUrl: normal.finalUrl,
    status: normal.status,
    bypassStatus: bypass.status,
    latencyMs: normal.latencyMs,
    contentType: normal.contentType,
    sizeBytes: normal.sizeBytes,
    truncated: normal.truncated,
    hash: normal.hash,
    bypassHash: bypass.hash,
    headers: normal.headers,
    ...analyzePair(normal, bypass, target.expectedText, expectedEdge, contentUpdatedAt),
    discoveredAssets: kind === "page" && /text\/html/i.test(normal.contentType)
      ? discoverAssets(normal.text, normal.finalUrl)
      : []
  };
}

function normalizeTargets(body) {
  if (!Array.isArray(body.targets) || body.targets.length === 0) {
    throw new Error("Add at least one page path or URL");
  }
  if (body.targets.length > MAX_TARGETS) throw new Error("A maximum of " + MAX_TARGETS + " page targets is allowed");

  let baseUrl = null;
  if (body.baseUrl) {
    try {
      baseUrl = new URL(body.baseUrl);
    } catch {
      throw new Error("Base website URL is invalid");
    }
  }

  return body.targets.map((target) => {
    const value = typeof target === "string" ? target : target?.value;
    const expectedText = typeof target === "object" ? String(target.expectedText || "").slice(0, 300) : "";
    if (!value || typeof value !== "string") throw new Error("Every target needs a URL or page path");
    let url;
    try {
      url = baseUrl ? new URL(value, baseUrl) : new URL(value);
    } catch {
      throw new Error("Invalid target: " + value);
    }
    return { url: url.href, expectedText };
  });
}

function allowedByRateLimit(request) {
  const key = request.socket.remoteAddress || "unknown";
  const now = Date.now();
  const current = rateLimits.get(key);
  if (!current || now - current.startedAt >= RATE_LIMIT_WINDOW_MS) {
    rateLimits.set(key, { startedAt: now, count: 1 });
    return true;
  }
  current.count += 1;
  return current.count <= RATE_LIMIT_REQUESTS;
}

async function handleVerification(request, response) {
  if (!allowedByRateLimit(request)) {
    sendJson(response, 429, { error: "Too many checks. Wait one minute and try again." });
    return;
  }
  try {
    const body = await readJson(request);
    const targets = normalizeTargets(body);
    const expectedEdge = String(body.expectedEdge || "").trim().slice(0, 100);
    let contentUpdatedAt = "";
    if (body.contentUpdatedAt) {
      const parsedUpdateTime = Date.parse(body.contentUpdatedAt);
      if (!Number.isFinite(parsedUpdateTime)) throw new Error("Content update time is invalid");
      contentUpdatedAt = new Date(parsedUpdateTime).toISOString();
    }
    const results = [];
    const warnings = [];

    for (const target of targets) {
      try {
        results.push(await inspectTarget(target, expectedEdge, contentUpdatedAt));
      } catch (error) {
        results.push({
          kind: "page",
          url: target.url,
          verdict: "error",
          rationale: error.name === "AbortError" ? "Request timed out after 15 seconds." : error.message
        });
      }
    }

    if (body.discoverAssets) {
      const discovered = [];
      const seen = new Set(targets.map(({ url }) => url));
      for (const result of results) {
        for (const url of result.discoveredAssets || []) {
          if (!seen.has(url) && discovered.length < MAX_DISCOVERED_ASSETS) {
            seen.add(url);
            discovered.push({ url, expectedText: "" });
          }
        }
      }
      for (const asset of discovered) {
        try {
          results.push(await inspectTarget(asset, expectedEdge, contentUpdatedAt, "asset"));
        } catch (error) {
          results.push({ kind: "asset", url: asset.url, verdict: "error", rationale: error.message });
        }
      }
      if (discovered.length === MAX_DISCOVERED_ASSETS) {
        warnings.push("Asset discovery is limited to " + MAX_DISCOVERED_ASSETS + " resources per run.");
      }
    }

    sendJson(response, 200, {
      checkedAt: new Date().toISOString(),
      results,
      warnings,
      note: "Delivery state and content recency are separate. A cache HIT is not automatically stale; an expected-content marker provides the strongest evidence."
    });
  } catch (error) {
    sendJson(response, 400, { error: error.message });
  }
}

async function serveStatic(request, response, pathname) {
  const relativePath = pathname === "/" ? "/compare.html" : pathname;
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(relativePath);
  } catch {
    sendJson(response, 400, { error: "Invalid URL" });
    return;
  }
  const filePath = path.resolve(PUBLIC_DIR, "." + decodedPath);
  if (filePath !== PUBLIC_DIR && !filePath.startsWith(PUBLIC_DIR + path.sep)) {
    sendJson(response, 403, { error: "Forbidden" });
    return;
  }
  try {
    const file = await stat(filePath);
    if (!file.isFile()) throw new Error("Not a file");
    response.writeHead(200, {
      "Content-Type": MIME_TYPES[path.extname(filePath).toLowerCase()] || "application/octet-stream",
      "Content-Length": file.size,
      "Cache-Control": path.extname(filePath) === ".html" ? "no-cache" : "public, max-age=3600"
    });
    if (request.method === "HEAD") response.end();
    else createReadStream(filePath).pipe(response);
  } catch {
    sendJson(response, 404, { error: "Not found" });
  }
}

export async function requestHandler(request, response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");

  const url = new URL(request.url, "http://localhost");
  if (request.method === "GET" && ["/healthz", "/readyz"].includes(url.pathname)) {
    sendJson(response, 200, { status: "ok", service: "cache-verifier" });
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/meta") {
    sendJson(response, 200, {
      name: "Cache Verifier",
      version: "2.1.0",
      maxTargets: MAX_TARGETS,
      maxDiscoveredAssets: MAX_DISCOVERED_ASSETS,
      maxBatchTargets: MAX_BATCH_TARGETS,
      features: ["environment-comparison", "batched-comparison", "partial-results", "forced-public-ip", "release-detection", "varnish-recency"]
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/check") {
    await handleVerification(request, response);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/compare") {
    if (!allowedByRateLimit(request)) {
      sendJson(response, 429, { error: "Too many checks. Wait one minute and try again." });
      return;
    }
    try {
      const body = await readJson(request);
      sendJson(response, 200, await runComparison(body));
    } catch (error) {
      sendJson(response, 400, { error: error.message });
    }
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/compare-batch") {
    if (!allowedByRateLimit(request)) {
      sendJson(response, 429, { error: "Too many comparison batches. Wait one minute and try again." });
      return;
    }
    try {
      const body = await readJson(request);
      if (!Array.isArray(body.targets) || body.targets.length > MAX_BATCH_TARGETS) {
        throw new Error("Each batch must contain between 1 and " + MAX_BATCH_TARGETS + " targets");
      }
      sendJson(response, 200, await runComparison(body));
    } catch (error) {
      sendJson(response, 400, { error: error.message });
    }
    return;
  }
  if (request.method === "GET" || request.method === "HEAD") {
    await serveStatic(request, response, url.pathname);
    return;
  }
  sendJson(response, 405, { error: "Method not allowed" });
}

export function startServer(port = Number(process.env.PORT || 3000)) {
  const server = createServer((request, response) => {
    requestHandler(request, response).catch((error) => {
      console.error("Request failed:", error);
      if (!response.headersSent) sendJson(response, 500, { error: "Internal server error" });
      else response.end();
    });
  });
  server.listen(port, "0.0.0.0", () => {
    console.log("Cache Verifier listening on 0.0.0.0:" + server.address().port);
  });
  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const server = startServer();
  const shutdown = () => server.close(() => process.exit(0));
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}
