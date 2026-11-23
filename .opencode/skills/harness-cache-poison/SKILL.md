---
name: harness-cache-poison
description: "Test web cache poisoning and HTTP request smuggling: unkeyed headers, cache key manipulation, CL.TE/TE.CL desync, and response queue poisoning."
---

# Cache poisoning & request smuggling — desync, unkeyed, queue

Source: `web-cache-poisoning`, `http-request-smuggling` (2024: H2.CL smuggling, cache key normalization, unkeyed query params, response queue poisoning).

## Gate

Approved `host` only. Every command via `cyber_process` `argv`. One probe per request. Never poison a cache shared with production users — use cache-buster query params for every probe. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Cache detection

Identify if the target uses a cache:
- Check headers: `X-Cache`, `CF-Cache-Status`, `Age`, `X-Cache-Hits`, `Vary`
- Send the same request twice → check if second is faster or has `X-Cache: HIT`
- Identify cache key: usually `Host + Path + Query` (but not always)
- Identify CDN: Cloudflare, Akamai, Fastly, CloudFront, Varnish

### 2. Unkeyed input discovery

For each header/parameter, check if it's reflected but NOT in the cache key:
| Input | Test |
|---|---|
| `X-Forwarded-Host` | `X-Forwarded-Host: evil.com` → reflected in `<link>`, `<script src>`? |
| `X-Forwarded-Scheme` | `X-Forwarded-Scheme: http` → redirect loop? |
| `X-Original-URL` | `X-Original-URL: /admin` → path override? |
| `X-Forwarded-Port` | Port reflected in URLs? |
| Cookie values | Specific cookie reflected but not in cache key? |
| `Accept-Language` | Language reflected without Vary? |
| Unkeyed query params | `?utm_content=<script>` reflected? |

Method: add a cache-buster (`?cb=random`), inject the header, request twice. If the second request (without the header) shows the injected value → cache poisoned.

### 3. Cache key normalization

Test differences between how the cache and the origin normalize the key:
- Path: `/api/..%2fadmin` vs `/api/../admin`
- Query: `?a=1&a=2` (parameter pollution)
- Fragment: `#fragment` (some caches strip, some don't)
- Case: `/Admin` vs `/admin`
- Encoding: `%61dmin` vs `admin`

### 4. HTTP request smuggling

#### CL.TE (front-end uses Content-Length, back-end uses Transfer-Encoding)
```
POST / HTTP/1.1
Host: target
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

#### TE.CL (front-end uses Transfer-Encoding, back-end uses Content-Length)
```
POST / HTTP/1.1
Host: target
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

#### H2.CL (HTTP/2 front-end, HTTP/1.1 back-end)
```
:method POST
:path /
content-length: 0

GET /admin HTTP/1.1
Host: target
```

Detection:
- Time-based: smuggled request causes a delay in the next response
- Response-based: next legitimate request receives the smuggled response
- Use `smuggler.py` or `http2smugl` for automated detection

### 5. Response queue poisoning

If smuggling is confirmed:
1. Smuggle a request to a sensitive endpoint (`/admin`, `/api/user`)
2. The next legitimate user's response contains the smuggled response
3. Prove with a canary: smuggle a request that reflects a unique token

### 6. Cache deception

Reverse of poisoning — trick the cache into storing a victim's private response:
- `GET /account/settings.css` (non-existent, but cache stores the HTML response)
- `GET /account/settings/..%2f..%2fstatic/style.css` (path confusion)
- If the cache stores the authenticated response under a public key → credential exposure

### 7. Negative controls

- Control 1: normal request → cached normally (positive control)
- Control 2: unkeyed header with no reflection → no poisoning
- Control 3: properly keyed input → cache varies correctly
- Control 4: for smuggling, a well-formed request → no desync

## Proof contract

A finding needs: (1) identified cache/proxy infrastructure, (2) demonstrated poisoning or smuggling with a canary, (3) a second request receiving the poisoned/smuggled response, (4) reproduction, (5) four negative controls. A reflected unkeyed header is a lead — cached reflection is a finding.

## Done

Each finding cites the cache infrastructure, the unkeyed input or desync technique, the cached/smuggled proof, and the negative controls.
