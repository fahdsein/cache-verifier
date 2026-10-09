# Cache Verifier

A deployable web service for checking whether public websites and CDN assets appear current or potentially stale. The browser UI calls its own Node.js backend, so cache headers are inspected server-side without browser CORS restrictions.

## What it checks

- HTTP status, response time, content type, and captured size
- Common cache headers: Age, Cache-Control, CDN-Cache-Control, CF-Cache-Status, X-Cache, Via, ETag, Last-Modified, and related edge headers
- Estimated age, maximum age, and remaining TTL
- Normal-response SHA-256 compared with a unique cache-bypassed request
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
- **Marker missing:** neither response contains it; the new content may not be deployed, or the marker may be incorrect.
- **Consistent:** both hashes match, but no marker was supplied.
- **Review:** hashes differ, the response is too large for a full comparison, or useful cache headers are unavailable.

Dynamic pages can legitimately produce different hashes. Treat a hash difference as a signal to investigate, not automatic proof of stale cache.

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

After deployment, verify:

1. Open the assigned public domain.
2. Open /healthz; it should return a JSON response with status **ok**.
3. Enter a public website URL and one page path.
4. Add a newest-content marker when possible.
5. Run the verification and export the CSV if you need evidence.

## Safety and operational limits

- Only public HTTP and HTTPS targets are allowed.
- Localhost, private, link-local, reserved, and multicast destinations are blocked to reduce SSRF risk.
- Redirect destinations are validated again.
- Each remote probe has a 15-second timeout.
- At most 20 page targets and 10 discovered assets are checked per run.
- Response capture is limited to 4 MiB per probe.
- The API is rate-limited per caller.
- The service does not store results or website content.

Deploy this service only for websites you are authorized to test. Each run creates real requests against the target.

## Scope limitation

The check runs from the NEO App service location. It can inspect the edge selected for that location, but it cannot prove the state of every CDN point of presence worldwide. Multi-region verification would require runners in multiple geographic regions.

## API

**POST /api/check**

~~~json
{
  "baseUrl": "https://example.com",
  "targets": [
    { "value": "/", "expectedText": "Example Domain" },
    { "value": "/assets/app.css", "expectedText": "" }
  ],
  "expectedEdge": "cloudflare",
  "discoverAssets": true
}
~~~

Other endpoints:

- GET /healthz
- GET /readyz
- GET /api/meta
