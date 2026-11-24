---
name: harness-source-deep
description: "Taint shipped JS from source to sink: recover maps, one sink class, quote file:line, benign function control; no live exploit from a string match."
---

# JS audit — taint in shipped bytes

Source: sourcemaps, webpack, `innerHTML`/`eval`/`fetch`. A minified name is a hypothesis.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Bundles already collected or in-scope URLs. Do not hit random CDNs. Secrets in JS → `harness-secret-scan`.

## Steps

### 1. Recover sources

```
cyber_process argv=["curl","-sS","-o","<evidence-dir>/app.js","<approved-js-url>"]
```

If `.map` exists, fetch it (same host). Hash both.

### 2. Inventory sinks

One class: DOM (`innerHTML`, `document.write`), network (`fetch`, `XMLHttpRequest`), storage, postMessage. Record `file:line` from the map or the bundle offset.

### 3. Taint one path

Source (`location.hash`, `postMessage`, query) → sink. Quote the connecting function. If a sanitizer sits on the path (DOMPurify), that is a control — bypass is another method (`harness-xss`).

### 4. Negative control

A nearby function that does **not** reach the sink, or a parameter that is not concatenated into the sink, must not be reported as tainted.

### 5. Endpoints

Regex/AST extract of `/api/` paths → `endpoints.json` observation for `harness-api-testing`. A path string is not a live route until probed there.

### 6. Finding contract

`cyber_finding` only when the sink is reachable **and** a runtime or XSS method confirms execution — otherwise candidate with `file:line`. Sources: map chunk. Checks: tainted path reproduction, benign function negative.

## Proof contract

A JS finding needs bundle hash, a quoted `file:line` taint path, runtime or XSS confirmation or an explicit candidate, and a benign-function negative control. A regex hit without a path is not a finding.

### Sink classes (one per pass)

| Class | Examples | Next method |
|---|---|---|
| DOM | innerHTML, document.write | xss |
| network | fetch, XHR | api-testing |
| storage | localStorage | secret-scan if token |
| postMessage | event.origin missing | xss |

```
cyber_process argv=["curl","-sS","-o","<evidence-dir>/app.js","<approved-js-url>"]
```

Quote `file:line` from the map. Benign nearby function is the negative control.

### Map recovery

If `.map` exists on the same host, fetch and hash it. Minified names are hypotheses until the map gives `file:line`. Endpoints extracted to `endpoints.json` are not live until `harness-api-testing`.

Sanitizer on the path (DOMPurify) is a control; bypass is `harness-xss`. Secrets in JS → `harness-secret-scan`.

### Stop

Random CDNs, claiming XSS from a string match, mixing four sink classes in one finding.

### Evidence ids

Bundle hash, map if any, one taint path `file:line`, benign-function negative control.

## Done

Evidence holds bundle hash, one sink `file:line`, negative control. String match without taint path is not a finding.
