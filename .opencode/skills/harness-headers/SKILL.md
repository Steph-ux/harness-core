---
name: harness-headers
description: "Audit security headers, CORS misconfiguration, CSP bypass, clickjacking, and cookie flags. Policy analysis with proof-of-concept."
---

# Headers — CORS, CSP, clickjacking, cookie flags

Source: `testing-cors`, `testing-csp`, `testing-clickjacking`, `security-headers` (2024: CORS null origin, CSP via JSONP on whitelisted CDN, SameSite=None+Secure bypass).

## Gate

Approved `host` only. Every command via `cyber_process` `argv`. Read-only analysis — no state modification. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Header inventory

Collect all response headers from the target:
```
curl -sI https://target/ | grep -iE "^(access-control|content-security|x-frame|x-content|strict-transport|referrer-policy|permissions-policy|set-cookie|x-xss|x-permitted)"
```

Record as baseline observation.

### 2. CORS analysis

Test the Origin reflection:
| Probe | What it proves |
|---|---|
| `Origin: https://evil.com` | Arbitrary origin reflected? |
| `Origin: null` | Null origin accepted? (file://, sandboxed iframe) |
| `Origin: https://target.evil.com` | Subdomain matching? |
| `Origin: https://targetevil.com` | Prefix matching? |
| No Origin header | Does ACAO appear without Origin? (wildcard) |

For each, check:
- `Access-Control-Allow-Origin` value
- `Access-Control-Allow-Credentials: true` (the critical flag)
- `Access-Control-Allow-Methods` and `Allow-Headers`

**Critical combo**: `ACAO: attacker-origin` + `ACAC: true` = credential theft via CORS.

### 3. CSP analysis

Parse the CSP header:
- `default-src`: the fallback
- `script-src`: where scripts can load from
- `object-src`: plugin sources (Flash, Java)
- `base-uri`: base tag hijack
- `form-action`: form submission targets
- `frame-ancestors`: clickjacking protection

Bypass checklist:
| CSP directive | Bypass |
|---|---|
| `script-src 'unsafe-inline'` | Direct `<script>` injection |
| `script-src cdn.example.com` | Find JSONP/callback endpoint on that CDN |
| `script-src 'nonce-X'` | Nonce reuse across requests? Nonce in DOM? |
| `script-src 'strict-dynamic'` | Inject via trusted script's DOM manipulation |
| No `object-src` | `<object data="data:text/html,...">` |
| No `base-uri` | `<base href="https://evil.com/">` hijacks relative URLs |
| `default-src 'self'` only | Upload a JS file to same origin |

### 4. Clickjacking

Check `X-Frame-Options` and `frame-ancestors`:
- Missing both → frameable
- `X-Frame-Options: SAMEORIGIN` without CSP `frame-ancestors` → browser-dependent
- Build a minimal PoC:
```html
<iframe src="https://target/sensitive-action" style="opacity:0.1;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<button style="position:relative;z-index:1">Click me</button>
```

### 5. Cookie flags

For each `Set-Cookie`:
- `Secure` flag present? (HTTPS only)
- `HttpOnly` flag present? (no JS access)
- `SameSite` value? (`Strict`, `Lax`, `None`)
- `SameSite=None` without `Secure` → browser rejects
- `Domain` scope → too broad? (`.example.com` includes subdomains)
- `Path` scope → too broad?
- `__Host-` prefix? `__Secure-` prefix?

### 6. Missing headers

| Header | Risk if missing |
|---|---|
| `Strict-Transport-Security` | Downgrade to HTTP |
| `X-Content-Type-Options: nosniff` | MIME sniffing → XSS |
| `Referrer-Policy` | Leaks URL parameters to third parties |
| `Permissions-Policy` | Unnecessary API access (camera, mic, geolocation) |

### 7. Negative controls

- Control 1: legitimate same-origin request works (positive control)
- Control 2: request without Origin → no ACAO reflection
- Control 3: CSP blocks an inline script on a page with strict policy

## Proof contract

A finding needs: (1) specific header misconfiguration identified, (2) PoC demonstrating the impact (CORS credential theft, CSP bypass with XSS, clickjacking frame), (3) reproduction, (4) negative controls. A missing header alone is informational unless paired with an exploitable condition.

## Done

Each finding cites the specific header value, the bypass or exploitation PoC, and the negative controls. Missing HSTS is informational; reflected ACAO+ACAC with credentials is high.
