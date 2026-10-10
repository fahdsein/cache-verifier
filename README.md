# Environment Cache Comparator

A deployable web service for locating content-recency differences between:

1. A staging candidate
2. The production static host or a selected public IP
3. The public production CDN seen by visitors

The browser calls its own Node.js backend, so cache and Varnish headers can be inspected without browser CORS restrictions. The original single-target API remains available at POST /api/check; the primary UI now uses POST /api/compare.

## Recommended BiznetGio workflow

Enter:

| Source | What to provide |
|---|---|
| Staging candidate | The staging website base URL |
| Production CDN | The public production website URL |
| Production static host | The production hostname; optionally force its connection to a selected public IP |

Then add paths such as:

~~~text
/
/pricing || New pricing headline
/version.json
/assets/app.css
/assets/app.js
/images/logo.svg
~~~

The tool runs normal and cache-bypassed probes against every configured source. It compares release IDs, expected text, static-file hashes, normalized HTML, cache timing, and Varnish evidence.

Root-cause results include:

- **All aligned:** staging, production host, and CDN match.
- **CDN stale:** production host has the new content, but CDN does not.
- **Not deployed:** staging is new, but the production host is still old.
- **Production differs:** production host and CDN agree but differ from staging.
- **Host differs:** staging and CDN agree but the selected host/IP differs.
- **All differ:** the result needs investigation for dynamic or environment-specific content.

## What it checks

- HTTP status, response time, content type, and captured size
- Common cache headers: Age, Date, Cache-Control, CDN-Cache-Control, CF-Cache-Status, X-Cache, X-Varnish, Via, Warning, ETag, Last-Modified, and related edge headers
- Estimated age, maximum age, and remaining TTL
- Varnish detection and separate HIT, MISS, PASS, PIPE, and GRACE delivery classification
- Three-source staging, production-host, and production-CDN comparison
- Optional forced public-IP connection with the hostname preserved for HTTP Host routing and TLS SNI
- TLS certificate verification and connected-IP evidence
- Automatic release detection from response headers, version JSON, or HTML meta tags
- Optional content-update time compared with the estimated cached-object time
- Normal-response SHA-256 compared with a unique cache-bypassed request
- Raw static-file hashes and normalized HTML hashes
- Optional newest-content text marker
- Optional CDN/edge identifier
- Up to 10 CSS, JavaScript, font, and image assets discovered from the checked HTML
- CSV export from the browser

Important: a CDN **HIT** means the CDN served a cached object; it does not prove that the object is old. For the strongest check, add text that only exists in the newest deployment:

~~~text
/pricing || New pricing effective October 2026
~~~

The result is:

- **Current:** the normal response contains the expected marker.
- **Stale:** only the cache-bypassed response contains the marker.
- **Likely current:** Date minus Age is at or after the supplied content-update time.
- **Possibly stale:** a Varnish hit appears to predate the supplied content-update time.
- **Grace:** Varnish explicitly reports that an expired object is being served inside its grace period.
- **Marker missing:** neither response contains it; the new content may not be deployed, or the marker may be incorrect.
- **Consistent:** both hashes match, but no marker was supplied.
- **Review:** hashes differ, the response is too large for a full comparison, or useful cache headers are unavailable.

Dynamic pages can legitimately produce different hashes. Treat a hash difference as a signal to investigate, not automatic proof of stale cache.

## Add a release identifier

Release identity is stronger than comparing cache headers. Add one of these to staging and production.

HTML:

~~~html
<meta name="release-id" content="git-commit-or-build-id">
<meta name="built-at" content="2026-10-10T09:30:00Z">
~~~

Or publish /version.json:

~~~json
{
  "releaseId": "a8c31f2",
  "builtAt": "2026-10-10T09:30:00Z",
  "environment": "production"
}
~~~

The verifier also recognizes X-Release-Id, X-Build-Id, and X-Deploy-Id response headers.

## Static host and forced-IP checks

For a shared HTTPS static host, do not replace the hostname with its IP in the URL. Instead use:

~~~text
Production static-host URL: https://www.example.com
Force connection to IP:    203.0.113.25
~~~

The verifier connects to the IP while retaining www.example.com for the HTTP Host header and TLS SNI. Certificate verification remains enabled. This is equivalent in purpose to resolving one hostname to a selected address for a single diagnostic request.

If the forced endpoint redirects to a different hostname, the check stops instead of silently switching to another infrastructure path.

## Varnish measurement

The verifier keeps **delivery state** and **content recency** separate:

- X-Cache values such as hit, miss, pass, and hit graced are treated as strong delivery evidence when the Varnish configuration exposes them.
- X-Varnish, Via, and Server are used to detect a Varnish layer.
- One versus multiple X-Varnish transaction IDs is displayed only as a low-confidence convention. The IDs are transaction identifiers, not cryptographic content fingerprints.
- A positive Age value means an object has cache age. It does not automatically mean stale content.
- Missing Age does not automatically mean a cache miss.

When **Content last updated** is supplied, the verifier calculates:

~~~text
estimated cached-object time = response Date - Age
~~~

A Varnish hit whose estimated time predates the update is marked **Possibly stale** with medium confidence. An expected newest-content marker remains stronger evidence.

For the clearest results, configure Varnish to expose an explicit X-Cache header from VCL. Without exposed cache headers, the tool can compare content but cannot definitively identify Varnish delivery behavior.

## Run locally

Requirements: Node.js 20 or newer.

~~~bash
npm start
~~~

Open <http://localhost:3000>.

Run checks:

~~~bash
npm test
npm run check
~~~

With Docker:

~~~bash
docker build -t cache-verifier .
docker run --rm -p 3000:3000 cache-verifier
~~~

## Deploy on NEO App

Push this folder as its own Git repository, or keep it inside a monorepo.

Create a **Web Service** and enter:

| NEO App field | Value |
|---|---|
| Repository URL | Your Git repository URL |
| Branch | main (or your actual branch) |
| Root directory | demo-example/cache-verifier for this workspace monorepo; leave blank if this folder is the repository root |
| Build type | Build File / Dockerfile |
| Build file | Dockerfile |
| Service/container port | 3000 |
| Health-check path | /readyz |
| Public access | Enabled |

No database, storage, queue, secret, or custom start command is required. The container starts with **npm start**, binds to **0.0.0.0**, and uses the platform-provided **PORT** when available. Do not manually set PORT unless NEO App specifically requires it.

After deployment:

1. Open the assigned public domain.
2. Open /healthz; it should return a JSON response with status **ok**.
3. Enter staging and production CDN URLs.
4. Add the production static-host URL and optional public IP.
5. Add page and static-asset paths.
6. Enter an expected release ID, expected page marker, or update time when available.
7. Run the comparison.
8. Export CSV for a flat evidence table or JSON for the complete report.

## Safety and operational limits

- Only public HTTP and HTTPS targets on ports 80 and 443 are allowed by the comparison endpoint.
- Localhost, private, link-local, reserved, and multicast destinations are blocked to reduce SSRF risk.
- Forced IPs must be public IPv4 or IPv6 addresses.
- Redirect destinations are validated again; cross-host redirects are rejected during forced-IP checks.
- The hostname is preserved for Host routing and TLS SNI, and TLS verification cannot be disabled.
- Each remote probe has a 15-second timeout.
- At most 20 page targets and 10 discovered assets are checked per run.
- Response capture is limited to 4 MiB per probe.
- The API is rate-limited per caller.
- The service does not store results or website content.

Deploy this service only for websites you are authorized to test. Each run creates real requests against the target.

## Scope limitation

The check runs from the NEO App service location. It can inspect the edge selected for that location, but it cannot prove the state of every CDN point of presence worldwide. Multi-region verification would require runners in multiple geographic regions.

## Comparison API

**POST /api/compare**

~~~json
{
  "profileName": "BiznetGio staging vs production",
  "environments": [
    {
      "key": "staging",
      "label": "Staging",
      "baseUrl": "https://staging.example.com"
    },
    {
      "key": "productionCdn",
      "label": "Production CDN",
      "baseUrl": "https://www.example.com"
    },
    {
      "key": "productionHost",
      "label": "Production host via IP",
      "baseUrl": "https://www.example.com",
      "overrideIp": "203.0.113.25"
    }
  ],
  "targets": [
    { "value": "/", "expectedText": "Example Domain" },
    { "value": "/assets/app.css", "expectedText": "" }
  ],
  "expectedReleaseId": "a8c31f2",
  "contentUpdatedAt": "2026-10-10T09:30:00.000Z",
  "normalizeHtml": true,
  "discoverAssets": true
}
~~~

The example IP above is documentation-only and will correctly be rejected by the running service. Replace it with an authorized routable public address.

Other endpoints:

- GET /healthz
- GET /readyz
- GET /api/meta
- POST /api/check for the legacy single-target workflow
