---
name: harness-api-testing
description: "Test an approved API in a fixed order: inventory, authentication, authorization, then input handling, with a negative control for each claim."
---

# API testing — inventory → auth → BOLA → input (2024 realities)

Source: `conducting-api-security-testing` (OpenAPI diff, BOLA-first, 2024 state).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Base URL, spec/OpenAPI, test accounts named in scope. Lowest-priv first. No real-customer mutation unless explicitly approved.

## Steps

1. Inventory from `endpoints.json`+`openapi.json`+`katana -jc`/`hakrawler`/`cariddi`/`paramspider` in `<evidence-dir>`. Diff documented vs observed → shadow → `harness-shadow-api`. Record observation.
2. Auth controls: each state-changing route `GET/POST` w/o cred → `401/403` (negative), then with low-priv cred → `200` baseline (positive). Both `cyber_process` `argv`.
3. BOLA: swap `id` to `id+1` or second identity's object. Re-read `GET /api/<resource>/<id>` to see leak. `200` error envelope is not leak.
4. Input: from `taint-inventory.json` / `semgrep --config p/xss,p/sqli,p/command-injection`, fuzz one tainted param with canary (`XSS-CANARY`, `SLEEP(2)`, `{{7*7}}`). Record.
5. Triage every candidate via `harness-vuln-triage` → `cyber_finding`. Add `cyber_capture` when visual.

### Coverage matrix

For every in-scope route record: method, path template, authentication state,
role, object reference, content type, rate-limit response, and whether the
operation is read or write. Test one representative route in each class:
public read, authenticated read, authenticated write, admin-only function,
file upload, webhook/callback, and batch/export. A route absent from the
documented contract is a shadow-API candidate, not automatically a flaw.

### Input and state controls

Use a harmless unique canary and one mutation at a time. For parsers compare
the canary in JSON, form, multipart, path, query, header and webhook fields.
For state changes capture before and after with a re-read; a response body or
HTTP 200 alone never proves persistence. Check method override, duplicate
parameters, content-type changes, pagination limits, cursor ownership and
idempotency keys only when the endpoint supports them.

### Proof contract

Each route gets an observation for the unauthenticated negative control and the
authorized baseline. A suspected authorization or input issue additionally
needs the exact mutated request, the server response, and a re-read or callback
showing the effect. Redact tokens, cookies, PII and request bodies that are not
needed to reproduce the claim. Unresolved routes remain `not-tested` with the
reason (missing account, unavailable environment, or scope restriction).

## Done

Every route has unauth+auth observations. Finding cites inventory `cyber_source` chunk + 2 controls + reproduction.
