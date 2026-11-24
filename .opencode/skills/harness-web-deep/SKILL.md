---
name: harness-web-deep
description: "Test SSRF, SSTI, XXE, deser, prototype pollution, race, upload, websocket, cache poison with one field per mutation, OOB or differential proof, and a benign control."
---

# Web deep — one field, one payload, OOB or differential

Source: SSRF IMDSv2, SSTI, XXE, deser, race, upload, websocket, cache. One class per pass if time is short.

## Gate

Approved `host+method+injection point` only. Every command `cyber_process` `argv`. One mutation per request. No full file read, no destructive delay, no shell. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Baseline

Same request, original value. Positive control.

```
cyber_process argv=["curl","-sS","-D","-","--data-binary","@orig.json","<url>"]
```

### 2. Classify the point

URL, header, JSON, form, XML, template, deserializer, or state transition. One harmless marker.

### 3. One payload for the chosen class

- SSRF: `http://127.0.0.1/` then metadata **only if cloud is in scope**; OOB token you control. Success = OOB or banner, not `200`.
- SSTI: `{{7*7}}`→`49`, then one other engine. One engine each.
- XXE: entity to a **marker file** you own, never `/etc/shadow`.
- Deser: sleep canary; duration vs control (`diff-control`).
- Pollution: `__proto__` then **read-back** of polluted object.
- Race: two state-changing requests ~50ms apart + final GET.
- Upload / websocket / cache: use the dedicated skill if loaded; else one probe and `not-tested` for the rest.

WAF/`5xx` is not confirmation — measure duration.

### 4. Negative controls

Original value: no OOB/no 49. Syntactically invalid payload: no hit. Out-of-scope host: not queried.

### 5. Finding contract

`cyber_finding` with baseline, payload, OOB or differential, original-value control, source chunk. Hash markers. File-upload/websocket/cache details stay in their skills when those are the claim.

### Class matrix (one row per pass)

| Class | Benign marker | Success | Control |
|---|---|---|---|
| SSRF | OOB URL you own | callback or 127 banner | original URL, no callback |
| SSTI | `{{7*7}}` | `49` in body | `{{7*8}}` not 56 |
| XXE | entity to your marker | marker in response | DTD disabled / no marker |
| Deser | sleep canary | delay > control median | original blob, no delay |
| Pollution | `__proto__.x=1` | read-back `x` | `{}` without proto |
| Race | two POSTs ~50ms | double state on GET | serial POSTs, single state |

Untested rows stay `not-tested` with the missing observation named.

### Argv examples (never a shell string)

```
cyber_process argv=["curl","-sS","-D","-","-H","Content-Type: application/json","--data-binary","@ssrf.json","<url>"]
cyber_process argv=["curl","-sS","-D","-","--data","q={{7*7}}","<url>"]
```

OOB listener is its own observation. Correlation id in the callback path.

### WAF

A block page is data. Record status, body hash, duration. Do not rotate five payloads in one observation. One encoding mutation per attempt (HTML entity, double URL, uncommon tag) then stop or open `harness-headers`.

## Done

Each class cites baseline, one payload, proof (OOB or persistence), and a control. Reflected canary alone is a lead.
