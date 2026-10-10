import { createHash, randomUUID } from "node:crypto";
import dns from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import net from "node:net";

const MAX_REMOTE_BYTES = 4 * 1024 * 1024;
const MAX_PATHS = 20;
const MAX_DISCOVERED_ASSETS = 10;
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 5;
const ALLOWED_ENVIRONMENT_KEYS = new Set(["staging", "productionCdn", "productionHost"]);
const OBSERVED_HEADERS = [
  "age", "cache-control", "cdn-cache-control", "cf-cache-status", "cf-ray", "date",
  "etag", "expires", "last-modified", "server", "surrogate-control", "via", "warning",
  "x-build-id", "x-cache", "x-cacheable", "x-cache-hits", "x-cdn", "x-deploy-id",
  "x-release-id", "x-served-by", "x-varnish", "x-vercel-cache"
];

function parseIpv4(address) {
  const parts = address.split(".").map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? parts
    : null;
}

export function isBlockedAddress(address) {
  const normalized = String(address || "").toLowerCase().split("%")[0];
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedAddress(mapped[1]);

  if (net.isIPv4(normalized)) {
    const parts = parseIpv4(normalized);
    if (!parts) return true;
    const [a, b, c] = parts;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }

  if (net.isIPv6(normalized)) {
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      /^fe[89ab]/.test(normalized) ||
      normalized.startsWith("ff") ||
      normalized.startsWith("2001:db8")
    );
  }
  return true;
}

function validatePort(url) {
  const port = url.port ? Number(url.port) : (url.protocol === "https:" ? 443 : 80);
  if (![80, 443].includes(port)) throw new Error("Only public HTTP ports 80 and 443 are allowed");
  return port;
}

async function resolvePublicUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Invalid URL: " + value);
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS URLs are allowed");
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed");
  validatePort(url);
  if (url.hostname.toLowerCase() === "localhost") throw new Error("Local and private targets are not allowed");
  const addresses = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some((entry) => isBlockedAddress(entry.address))) {
    throw new Error("Local, reserved, and private targets are not allowed");
  }
  return { url, address: addresses[0].address, family: addresses[0].family };
}

function validateOverrideIp(value) {
  const address = String(value || "").trim();
  const family = net.isIP(address);
  if (!family) throw new Error("Connection override must be a valid IPv4 or IPv6 address");
  if (isBlockedAddress(address)) throw new Error("Connection override must be a routable public IP address");
  return { address, family };
}

function observedHeaders(headers) {
  const output = {};
  for (const name of OBSERVED_HEADERS) {
    const value = headers[name];
    if (value !== undefined) output[name] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return output;
}

function fixedLookup(address, family) {
  return (_hostname, options, callback) => {
    if (options?.all) {
      callback(null, [{ address, family }]);
      return;
    }
    callback(null, address, family);
  };
}

async function requestOnce(url, pinned, bypass) {
  const startedAt = performance.now();
  const requestHeaders = {
    Accept: "*/*",
    "Accept-Encoding": "identity",
    Host: url.host,
    "User-Agent": "CacheVerifier/2.0 (+multi-environment diagnostic)"
  };
  if (bypass) {
    requestHeaders["Cache-Control"] = "no-cache";
    requestHeaders.Pragma = "no-cache";
  }
  const isTls = url.protocol === "https:";
  const transport = isTls ? httpsRequest : httpRequest;
  const options = {
    protocol: url.protocol,
    hostname: url.hostname,
    port: validatePort(url),
    path: url.pathname + url.search,
    method: "GET",
    headers: requestHeaders,
    agent: false,
    lookup: fixedLookup(pinned.address, pinned.family)
  };
  if (isTls) {
    options.servername = net.isIP(url.hostname) ? undefined : url.hostname;
    options.rejectUnauthorized = true;
  }

  return await new Promise((resolve, reject) => {
    const request = transport(options, (response) => {
      const chunks = [];
      let size = 0;
      let truncated = false;
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        const buffer = Buffer.concat(chunks);
        const contentType = String(response.headers["content-type"] || "");
        const isText = /(?:text\/|json|javascript|xml|svg)/i.test(contentType);
        const socket = response.socket;
        let tls = null;
        if (isTls) {
          const certificate = typeof socket.getPeerCertificate === "function" ? socket.getPeerCertificate() : {};
          tls = {
            authorized: Boolean(socket.authorized),
            authorizationError: socket.authorizationError || "",
            servername: options.servername || "",
            subject: certificate?.subject?.CN || "",
            subjectAltName: certificate?.subjectaltname || "",
            validTo: certificate?.valid_to || "",
            fingerprint256: certificate?.fingerprint256 || ""
          };
        }
        resolve({
          status: response.statusCode || 0,
          ok: (response.statusCode || 0) >= 200 && (response.statusCode || 0) < 400,
          latencyMs: Math.round(performance.now() - startedAt),
          contentType,
          sizeBytes: buffer.length,
          truncated,
          hash: createHash("sha256").update(buffer).digest("hex"),
          text: isText ? buffer.toString("utf8") : "",
          headers: observedHeaders(response.headers),
          location: response.headers.location || "",
          connectedIp: socket.remoteAddress || pinned.address,
          requestedHost: url.host,
          tls
        });
      };
      response.on("data", (chunk) => {
        if (truncated) return;
        if (size + chunk.length > MAX_REMOTE_BYTES) {
          const remaining = Math.max(0, MAX_REMOTE_BYTES - size);
          if (remaining) chunks.push(chunk.subarray(0, remaining));
          size += remaining;
          truncated = true;
          finish();
          response.destroy();
          return;
        }
        chunks.push(chunk);
        size += chunk.length;
      });
      response.on("end", finish);
      response.on("error", (error) => truncated ? finish() : reject(error));
    });
    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      const error = new Error("Request timed out after 15 seconds");
      error.name = "AbortError";
      request.destroy(error);
    });
    request.once("error", reject);
    request.end();
  });
}

async function fetchPinned(initialUrl, overrideIp, bypass = false) {
  const original = new URL(initialUrl);
  let current = new URL(initialUrl);
  if (bypass) current.searchParams.set("__cache_verifier", Date.now() + "-" + randomUUID().slice(0, 8));

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    let pinned;
    if (overrideIp) {
      if (current.hostname !== original.hostname) {
        throw new Error("A forced-IP request redirected to another hostname; comparison stopped to avoid a misleading result");
      }
      pinned = validateOverrideIp(overrideIp);
      validatePort(current);
    } else {
      const resolved = await resolvePublicUrl(current.href);
      pinned = { address: resolved.address, family: resolved.family };
    }

    const response = await requestOnce(current, pinned, bypass);
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      if (!response.location) throw new Error("Redirect response did not include a Location header");
      if (redirects === MAX_REDIRECTS) throw new Error("Too many redirects");
      current = new URL(response.location, current);
      continue;
    }
    return { ...response, finalUrl: current.href, overrideIp: overrideIp || "" };
  }
  throw new Error("Too many redirects");
}

function classifyCache(headers) {
  const signal = [
    headers["cf-cache-status"], headers["x-vercel-cache"], headers["x-cache"],
    headers["x-cache-hits"], headers["cdn-cache-control"]
  ].filter(Boolean).join(" ").toUpperCase();
  for (const state of ["GRACE", "STALE", "REVALIDATED", "EXPIRED", "BYPASS", "PASS", "PIPE", "DYNAMIC", "MISS", "HIT"]) {
    if (signal.includes(state)) return state;
  }
  return Number(headers.age || 0) > 0 ? "HIT (inferred)" : "UNKNOWN";
}

function detectVarnish(headers) {
  const xVarnish = String(headers["x-varnish"] || "");
  const xCache = String(headers["x-cache"] || "").toLowerCase();
  const detected = Boolean(xVarnish || /varnish/i.test(headers.via || "") || /varnish/i.test(headers.server || ""));
  const transactionIds = (xVarnish.match(/\d+/g) || []).slice(0, 8);
  let delivery = "UNKNOWN";
  let confidence = "none";
  let evidence = detected ? "Varnish signature found without an explicit delivery result." : "No Varnish signature was exposed.";
  if (/hit\s+graced|grace/.test(xCache)) {
    delivery = "GRACE"; confidence = "high"; evidence = "X-Cache reports a graced hit.";
  } else if (/\bhit\b/.test(xCache)) {
    delivery = "HIT"; confidence = "high"; evidence = "X-Cache explicitly reports a cache hit.";
  } else if (/\bmiss\b/.test(xCache)) {
    delivery = "MISS"; confidence = "high"; evidence = "X-Cache explicitly reports a cache miss.";
  } else if (/\bpass\b/.test(xCache)) {
    delivery = "PASS"; confidence = "high"; evidence = "X-Cache explicitly reports a cache pass.";
  } else if (/\bpipe\b/.test(xCache)) {
    delivery = "PIPE"; confidence = "high"; evidence = "X-Cache explicitly reports a piped request.";
  } else if (detected && transactionIds.length >= 2) {
    delivery = "LIKELY HIT"; confidence = "low"; evidence = "Multiple X-Varnish IDs suggest a hit by convention only.";
  } else if (detected && transactionIds.length === 1) {
    delivery = "LIKELY MISS"; confidence = "low"; evidence = "One X-Varnish ID suggests a miss by convention only.";
  }
  return { detected, delivery, confidence, evidence, transactionIds };
}

function calculateTtl(headers) {
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

function estimateCacheTime(headers) {
  if (!headers.date || headers.age === undefined) return null;
  const responseTime = Date.parse(headers.date);
  const ageSeconds = Number(headers.age);
  if (!Number.isFinite(responseTime) || !Number.isFinite(ageSeconds) || ageSeconds < 0) return null;
  return new Date(responseTime - ageSeconds * 1000).toISOString();
}

function parseAttributes(tag) {
  const attributes = {};
  const pattern = /([:\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
  let match;
  while ((match = pattern.exec(tag))) attributes[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? "";
  return attributes;
}

export function extractReleaseInfo(text, contentType, headers = {}) {
  for (const name of ["x-release-id", "x-build-id", "x-deploy-id"]) {
    if (headers[name]) return { releaseId: headers[name], builtAt: "", source: "response header " + name };
  }
  if (/json/i.test(contentType || "")) {
    try {
      const value = JSON.parse(text);
      const releaseId = value.releaseId || value.release_id || value.buildId || value.build_id || value.commit || value.sha || value.version;
      const builtAt = value.builtAt || value.built_at || value.buildTime || value.build_time || "";
      if (releaseId) return { releaseId: String(releaseId), builtAt: String(builtAt || ""), source: "JSON document" };
    } catch {
      // Continue with text and HTML detection.
    }
  }
  if (/html/i.test(contentType || "")) {
    let releaseId = "";
    let builtAt = "";
    for (const match of text.matchAll(/<meta\b[^>]*>/gi)) {
      const attributes = parseAttributes(match[0]);
      const name = String(attributes.name || attributes.property || "").toLowerCase();
      if (/^(release-id|build-id|deploy-id|git-commit|version)$/.test(name)) releaseId = attributes.content || "";
      if (/^(built-at|build-time|deployed-at)$/.test(name)) builtAt = attributes.content || "";
    }
    if (releaseId || builtAt) return { releaseId, builtAt, source: "HTML meta tag" };
  }
  return { releaseId: "", builtAt: "", source: "" };
}

export function normalizeHtmlContent(text, origin = "") {
  let normalized = String(text || "");
  if (origin) normalized = normalized.split(origin).join("{ORIGIN}");
  return normalized
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/\snonce\s*=\s*(?:"[^"]*"|'[^']*')/gi, ' nonce=""')
    .replace(/\sdata-request-id\s*=\s*(?:"[^"]*"|'[^']*')/gi, ' data-request-id=""')
    .replace(/>\s+</g, "><")
    .replace(/\s+/g, " ")
    .trim();
}

function discoverSameOriginAssets(html, pageUrl, limit = MAX_DISCOVERED_ASSETS) {
  const assets = [];
  const seen = new Set();
  const base = new URL(pageUrl);
  const pattern = /(?:src|href)\s*=\s*["']([^"'#]+)["']/gi;
  let match;
  while ((match = pattern.exec(html)) && assets.length < limit) {
    try {
      const url = new URL(match[1], base);
      if (url.origin !== base.origin) continue;
      if (!/\.(?:css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf)(?:\?|$)/i.test(url.pathname + url.search)) continue;
      const value = url.pathname + url.search;
      if (seen.has(value)) continue;
      seen.add(value);
      assets.push(value);
    } catch {
      // Ignore malformed asset references.
    }
  }
  return assets;
}

function recencyForSnapshot(normal, bypass, options) {
  const expectedText = options.expectedText || "";
  const expectedReleaseId = options.expectedReleaseId || "";
  const contentUpdatedAt = options.contentUpdatedAt || "";
  const varnish = detectVarnish(normal.headers);
  const cacheState = classifyCache(normal.headers);
  const delivery = varnish.detected && varnish.delivery !== "UNKNOWN" ? varnish.delivery : cacheState;
  const estimatedCachedAt = estimateCacheTime(normal.headers);
  const normalContains = expectedText ? normal.text.includes(expectedText) : null;
  const bypassContains = expectedText ? bypass.text.includes(expectedText) : null;
  const normalRelease = extractReleaseInfo(normal.text, normal.contentType, normal.headers);
  const bypassRelease = extractReleaseInfo(bypass.text, bypass.contentType, bypass.headers);
  let verdict = "consistent";
  let confidence = "low";
  let rationale = "Normal and cache-bypassed response hashes match.";

  if (!normal.ok) {
    verdict = "error"; confidence = "high"; rationale = "The endpoint returned HTTP " + normal.status + ".";
  } else if (!bypass.ok) {
    verdict = "unverifiable"; rationale = "The bypass probe returned HTTP " + bypass.status + ".";
  } else if (expectedReleaseId && normalRelease.releaseId === expectedReleaseId) {
    verdict = "current"; confidence = "high"; rationale = "The expected release ID is present in the normal response.";
  } else if (expectedReleaseId && normalRelease.releaseId !== expectedReleaseId && bypassRelease.releaseId === expectedReleaseId) {
    verdict = "stale"; confidence = "high"; rationale = "The expected release ID appears only in the bypass response.";
  } else if (expectedText && normalContains) {
    verdict = "current"; confidence = "high"; rationale = "The expected newest-content marker is present.";
  } else if (expectedText && !normalContains && bypassContains) {
    verdict = "stale"; confidence = "high"; rationale = "The expected marker appears only after cache bypass.";
  } else if (expectedText && !normalContains && !bypassContains) {
    verdict = "marker-missing"; confidence = "medium"; rationale = "The expected marker is missing from both probes.";
  } else if (contentUpdatedAt && estimatedCachedAt && Date.parse(estimatedCachedAt) < Date.parse(contentUpdatedAt) && /HIT|GRACE/.test(delivery)) {
    verdict = "possible-stale"; confidence = "medium"; rationale = "Estimated cache time predates the supplied update time.";
  } else if (delivery === "GRACE") {
    verdict = "grace"; confidence = "medium"; rationale = "An expired object appears to be served within Varnish grace.";
  } else if (normal.hash !== bypass.hash) {
    verdict = "different"; rationale = "Normal and cache-bypassed content differs.";
  } else if (normal.truncated || bypass.truncated) {
    verdict = "limited"; rationale = "The comparison covers only the first 4 MiB.";
  }

  return {
    verdict,
    confidence,
    rationale,
    cacheState,
    delivery,
    varnish,
    ttl: calculateTtl(normal.headers),
    estimatedCachedAt,
    expectedTextFound: normalContains,
    bypassExpectedTextFound: bypassContains,
    release: normalRelease
  };
}

async function inspectEnvironment(environment, target, options, kind) {
  const url = new URL(target.value, environment.baseUrl).href;
  const normal = await fetchPinned(url, environment.overrideIp, false);
  const bypass = await fetchPinned(url, environment.overrideIp, true);
  const recency = recencyForSnapshot(normal, bypass, {
    expectedText: target.expectedText,
    expectedReleaseId: options.expectedReleaseId,
    contentUpdatedAt: options.contentUpdatedAt
  });
  const isHtml = /text\/html/i.test(normal.contentType);
  let normalizedHash = normal.hash;
  if (isHtml && options.normalizeHtml) {
    const origin = new URL(normal.finalUrl).origin;
    normalizedHash = createHash("sha256").update(normalizeHtmlContent(normal.text, origin)).digest("hex");
  }
  return {
    environment: environment.key,
    label: environment.label,
    kind,
    url,
    finalUrl: normal.finalUrl,
    status: normal.status,
    bypassStatus: bypass.status,
    latencyMs: normal.latencyMs,
    contentType: normal.contentType,
    sizeBytes: normal.sizeBytes,
    truncated: normal.truncated,
    hash: normal.hash,
    normalizedHash,
    bypassHash: bypass.hash,
    connectedIp: normal.connectedIp,
    requestedHost: normal.requestedHost,
    overrideIp: normal.overrideIp,
    tls: normal.tls,
    headers: normal.headers,
    ...recency,
    _text: normal.text,
    _assets: isHtml ? discoverSameOriginAssets(normal.text, normal.finalUrl) : []
  };
}

function comparisonHash(snapshot, normalizeHtml) {
  if (!snapshot || snapshot.verdict === "error") return "";
  return normalizeHtml && /text\/html/i.test(snapshot.contentType) ? snapshot.normalizedHash : snapshot.hash;
}

export function compareEnvironmentSnapshots(snapshots, target, options) {
  const staging = snapshots.find((item) => item.environment === "staging");
  const cdn = snapshots.find((item) => item.environment === "productionCdn");
  const host = snapshots.find((item) => item.environment === "productionHost");
  if (!staging || !cdn) {
    return { code: "error", label: "Incomplete", severity: "error", confidence: "high", rationale: "Staging or production CDN result is missing." };
  }
  if ([staging, cdn, host].filter(Boolean).some((item) => item.verdict === "error")) {
    return { code: "error", label: "Request error", severity: "error", confidence: "high", rationale: "At least one environment could not be checked." };
  }

  const expectedReleaseId = options.expectedReleaseId || "";
  if (expectedReleaseId) {
    if (cdn.release.releaseId === expectedReleaseId) {
      return { code: "current", label: "Production current", severity: "good", confidence: "high", rationale: "Production CDN exposes the expected release ID." };
    }
    if (host && host.release.releaseId === expectedReleaseId && cdn.release.releaseId !== expectedReleaseId) {
      return { code: "cdn-stale", label: "CDN stale", severity: "bad", confidence: "high", rationale: "Production host has the expected release, but production CDN does not." };
    }
    if (host && host.release.releaseId !== expectedReleaseId) {
      return { code: "not-deployed", label: "Not deployed", severity: "warn", confidence: "high", rationale: "Production host does not expose the expected release ID." };
    }
  }

  if (target.expectedText) {
    if (cdn.expectedTextFound) {
      return { code: "current", label: "Production current", severity: "good", confidence: "high", rationale: "Production CDN contains the expected newest-content marker." };
    }
    if (host && host.expectedTextFound && !cdn.expectedTextFound) {
      return { code: "cdn-stale", label: "CDN stale", severity: "bad", confidence: "high", rationale: "Production host contains the marker, but production CDN does not." };
    }
    if (staging.expectedTextFound && (!host || !host.expectedTextFound)) {
      return { code: "not-deployed", label: "Not deployed", severity: "warn", confidence: "high", rationale: "Staging contains the marker, but the production host does not." };
    }
  }

  if (host && cdn.verdict === "possible-stale" && ["current", "consistent"].includes(host.verdict)) {
    return { code: "cdn-stale", label: "CDN possibly stale", severity: "bad", confidence: "medium", rationale: "CDN cache timing predates the update while the production host does not show the same warning." };
  }

  const stagingHash = comparisonHash(staging, options.normalizeHtml);
  const cdnHash = comparisonHash(cdn, options.normalizeHtml);
  const hostHash = comparisonHash(host, options.normalizeHtml);
  if (host) {
    if (stagingHash && stagingHash === hostHash && hostHash === cdnHash) {
      return { code: "aligned", label: "All aligned", severity: "good", confidence: "medium", rationale: "Staging, production host, and production CDN content hashes match." };
    }
    if (stagingHash && stagingHash === hostHash && hostHash !== cdnHash) {
      return { code: "cdn-stale", label: "CDN differs", severity: "bad", confidence: "medium", rationale: "Production host matches staging, but production CDN serves different content." };
    }
    if (hostHash && hostHash === cdnHash && stagingHash !== hostHash) {
      return { code: "prod-differs", label: "Production differs", severity: "warn", confidence: "medium", rationale: "Production host and CDN agree, but both differ from staging." };
    }
    if (stagingHash && stagingHash === cdnHash && hostHash !== stagingHash) {
      return { code: "host-differs", label: "Host differs", severity: "warn", confidence: "medium", rationale: "Staging and production CDN agree, but the selected production host differs." };
    }
    return { code: "diverged", label: "All differ", severity: "warn", confidence: "low", rationale: "The three sources differ. Dynamic content or environment-specific configuration may be involved." };
  }
  if (stagingHash && stagingHash === cdnHash) {
    return { code: "aligned", label: "Aligned", severity: "good", confidence: "medium", rationale: "Staging and production CDN content hashes match." };
  }
  return { code: "prod-differs", label: "Production differs", severity: "warn", confidence: "low", rationale: "Production CDN differs from staging; no production-host checkpoint was provided." };
}

function normalizeEnvironment(value) {
  const key = String(value?.key || "");
  if (!ALLOWED_ENVIRONMENT_KEYS.has(key)) throw new Error("Unknown comparison environment");
  const label = String(value.label || key).slice(0, 60);
  let baseUrl;
  try {
    baseUrl = new URL(value.baseUrl);
  } catch {
    throw new Error(label + " base URL is invalid");
  }
  if (!["http:", "https:"].includes(baseUrl.protocol)) throw new Error(label + " must use HTTP or HTTPS");
  if (baseUrl.username || baseUrl.password) throw new Error(label + " URL cannot contain credentials");
  validatePort(baseUrl);
  const overrideIp = String(value.overrideIp || "").trim();
  if (overrideIp) validateOverrideIp(overrideIp);
  return { key, label, baseUrl: baseUrl.href, overrideIp };
}

function normalizeTarget(value) {
  const raw = typeof value === "string" ? value : value?.value;
  if (!raw || typeof raw !== "string") throw new Error("Every comparison target needs a path");
  let pathValue = raw.trim();
  if (/^https?:\/\//i.test(pathValue)) {
    const parsed = new URL(pathValue);
    pathValue = parsed.pathname + parsed.search;
  }
  if (!pathValue.startsWith("/")) pathValue = "/" + pathValue;
  return {
    value: pathValue,
    expectedText: typeof value === "object" ? String(value.expectedText || "").slice(0, 300) : ""
  };
}

function cleanSnapshot(snapshot) {
  const { _text, _assets, ...clean } = snapshot;
  return clean;
}

export async function runComparison(body) {
  const environments = Array.isArray(body.environments) ? body.environments.filter((item) => item?.baseUrl).map(normalizeEnvironment) : [];
  if (!environments.some((item) => item.key === "staging")) throw new Error("Staging base URL is required");
  if (!environments.some((item) => item.key === "productionCdn")) throw new Error("Production CDN base URL is required");
  if (new Set(environments.map((item) => item.key)).size !== environments.length) throw new Error("Comparison environments must be unique");

  let targets = Array.isArray(body.targets) ? body.targets.map(normalizeTarget) : [];
  if (!targets.length) throw new Error("Add at least one page or asset path");
  if (targets.length > MAX_PATHS) throw new Error("A maximum of " + MAX_PATHS + " paths is allowed");
  let contentUpdatedAt = "";
  if (body.contentUpdatedAt) {
    const parsed = Date.parse(body.contentUpdatedAt);
    if (!Number.isFinite(parsed)) throw new Error("Content update time is invalid");
    contentUpdatedAt = new Date(parsed).toISOString();
  }
  const options = {
    normalizeHtml: body.normalizeHtml !== false,
    expectedReleaseId: String(body.expectedReleaseId || "").trim().slice(0, 160),
    contentUpdatedAt
  };
  const warnings = [];
  const results = [];
  const seenPaths = new Set(targets.map((target) => target.value));

  for (let index = 0; index < targets.length; index += 1) {
    const target = targets[index];
    const kind = index >= (body.targets?.length || 0) ? "asset" : "page";
    const snapshots = await Promise.all(environments.map(async (environment) => {
      try {
        return await inspectEnvironment(environment, target, options, kind);
      } catch (error) {
        return {
          environment: environment.key,
          label: environment.label,
          kind,
          url: new URL(target.value, environment.baseUrl).href,
          verdict: "error",
          confidence: "high",
          rationale: error.name === "AbortError" ? "Request timed out after 15 seconds." : error.message,
          release: { releaseId: "", builtAt: "", source: "" },
          headers: {}
        };
      }
    }));
    const comparison = compareEnvironmentSnapshots(snapshots, target, options);
    results.push({
      path: target.value,
      kind,
      expectedText: target.expectedText,
      comparison,
      snapshots: snapshots.map(cleanSnapshot)
    });

    if (body.discoverAssets && kind === "page") {
      const staging = snapshots.find((item) => item.environment === "staging");
      for (const asset of staging?._assets || []) {
        if (seenPaths.size >= MAX_PATHS + MAX_DISCOVERED_ASSETS) break;
        if (!seenPaths.has(asset)) {
          seenPaths.add(asset);
          targets.push({ value: asset, expectedText: "" });
        }
      }
    }
  }

  if (targets.length > MAX_PATHS) warnings.push("Asset discovery added up to " + MAX_DISCOVERED_ASSETS + " same-origin static resources.");
  if (environments.some((item) => item.overrideIp)) {
    warnings.push("Forced-IP checks preserve the URL hostname for Host routing and TLS SNI; TLS certificate verification remains enabled.");
  }
  const summary = {
    total: results.length,
    current: results.filter((item) => item.comparison.severity === "good").length,
    cdnStale: results.filter((item) => item.comparison.code === "cdn-stale").length,
    review: results.filter((item) => item.comparison.severity === "warn").length,
    errors: results.filter((item) => item.comparison.severity === "error").length
  };
  return {
    profileName: String(body.profileName || "Environment comparison").slice(0, 100),
    checkedAt: new Date().toISOString(),
    environments,
    options,
    summary,
    warnings,
    results,
    note: "A matching release ID or expected marker is stronger evidence than cache headers or hashes alone."
  };
}
