---
name: harness-api-testing
description: "Test an approved API in order: inventory, unauth negative, low-priv baseline, BOLA, one input canary; every claim has a control; 200 envelope is not a leak."
---

# API testing — inventory → auth → BOLA → input

Source: OpenAPI diff, BOLA-first. Shadow routes go to `harness-shadow-api`.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Base URL, spec, and test accounts named in scope. Lowest-priv first. No real-customer mutation unless explicitly approved.

## Steps

### 1. Inventory

From `openapi.json` + crawl already in evidence. Diff documented vs observed. Record one observation. `cyber_source` the spec.

```
cyber_process argv=["curl","-sS","-D","-","<base>/.well-known/openapi.json"]
```

Missing spec → harvest from client (`harness-source-deep`), still one inventory obs.

### 2. Auth controls (every state-changing class)

Unauth `GET/POST` → expect `401`/`403` (negative control). Low-priv cred → `200` baseline (positive). Both via `cyber_process` `argv`. One representative of: public read, auth read, auth write, admin function, upload, webhook, batch/export. Untested class stays `not-tested`.

### 3. BOLA

Swap `id` to a second identity's object or `id+1` **only if** that id is a test object. Re-read `GET`. Error envelope `200` is not a leak. Detail: `harness-idor`.

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <token-A>","<url>/api/<res>/<B-id>"]
```

### 4. One input canary

One tainted param from `taint-inventory.json` / semgrep: `XSS-CANARY`, `SLEEP` is **out** unless SQLi method is loaded. Prefer a unique marker. JSON vs form vs header: one transport.

### 5. Method override / duplicate params

Only if the endpoint supports them: `_method=DELETE`, duplicate `id`. One extra probe, then stop.

### 6. Finding contract

Triage via `harness-vuln-triage`. `cyber_finding` with inventory source, unauth negative, auth positive, mutated request, re-read or callback. Redact tokens. Capture if visual, linked to the re-read.

### Route-class matrix

| Class | Unauth | Low-priv | Extra |
|---|---|---|---|
| Public read | 200 ok | n/a | n/a |
| Auth read | 401/403 | 200 + own fields | BOLA other-id |
| Auth write | 401/403 | 200 + re-read | one-field mass assign |
| Admin function | 401/403 | 403 | high-priv positive |
| Upload | 401/403 | `harness-file-upload` | n/a |
| Webhook | unauth reject | signed body | replay control |
| Batch/export | 401/403 | own rows only | cursor ownership |

A class not in the spec stays `not-tested`. Pagination, method override and duplicate parameters are extra rows, not a substitute for the matrix.

### Evidence ids

Inventory, unauth, low-priv, optional BOLA/canary. Spec chunk as `cyber_source`. Untested route classes stay `not-tested`.

### Input canary

One tainted param, one transport (JSON/form/header). Marker unique. `SLEEP` only if `harness-sqli` is loaded. Method override / duplicate `id` only if the endpoint supports them — one extra probe.

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <low>","<url>"]
```

BOLA detail is `harness-idor`. Shadow routes are `harness-shadow-api`. Triage every candidate.

### Stop

Real-customer mutation, mixing five classes in one observation, promoting OpenAPI "might be IDOR".

### Evidence ids

Inventory, unauth negative control, low-priv positive, optional BOLA/canary, spec chunk.

## Done

Every claimed route has unauth+auth observations. A finding cites the spec chunk + two controls + reproduction.
