---
name: harness-shadow-api
description: "Diff documented OpenAPI/GraphQL against observed traffic; HEAD/GET one in-scope shadow candidate; invalid-sibling control; 200 is existence not impact."
---

# Shadow API — doc vs observed, one live probe

Source: OpenAPI, HAR, crawl. Stale archive URLs are not shadows.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Use collected evidence first. Wordlist brute only if the engagement allows content discovery, never off-host. Do not POST/PUT/DELETE merely to prove a route exists.

## Steps

### 1. Documented set

`cyber_source` `openapi.json` / GraphQL schema / vendor doc. Normalize `method + path template + host` (case, slash, encoding, version prefix, GraphQL operation name).

### 2. Observed set

Attack-surface URLs, katana/HAR/BBOT, same host. Keep auth and content-type on the record.

### 3. Diff

`observed − documented` on the **same host** = candidates. Other host = out of scope, not shadow. Health/static asset paths are not enough.

### 4. One live probe

HEAD or harmless GET:

```
cyber_process argv=["curl","-sS","-D","-","-o","NUL","-X","HEAD","<approved-url>"]
```

Record status, content-type, body hash, redirect, auth requirement. `404` = not a shadow. `200` → `harness-vuln-triage` (resource vs error page).

Negative control: known-invalid sibling path on the same host (`/this-route-does-not-exist-<id>`).

### 5. Finding contract

One shadow → one `cyber_finding`: contract obs + observed-list + live probe + documented-absence + sibling 404. Impact (IDOR, data, state) is `harness-idor` / `harness-access-control` / `harness-business-logic` with new observations.

## Proof contract

A shadow finding needs: (1) documented host+method+path template, (2) observed equivalent that survives normalization, (3) live HEAD/GET on the approved URL, (4) sibling 404 or documented-absence control. A crawl hit without a live probe stays a candidate. Authorization impact is a different method.

### Diff rules

Normalize method, host, path case, slash, encoding, version prefix, GraphQL operation. Same host only.

```
cyber_process argv=["curl","-sS","-D","-","-o","NUL","-X","HEAD","<approved-url>"]
```

| Result | Meaning |
|---|---|
| 404 | not a shadow |
| 200 error page | triage |
| 200 resource | shadow existence; impact is another method |

No POST/PUT/DELETE merely to prove the route.

### Auth and type

Keep authentication and content-type on the observed record. Health/static assets are not shadows. Stale archive URLs are not shadows.

Impact (IDOR, data, state) is `harness-idor` / `harness-access-control` / `harness-business-logic` with **new** observations. This method only proves undocumented existence.

### Stop

Wordlist off-host, POST/PUT/DELETE merely to prove the route, claiming BOLA from a HEAD 200.

### Evidence ids

Contract source, observed-list, live HEAD/GET, sibling 404 negative control.

## Done

Each shadow cites contract, crawl, live probe, sibling control. A 200 alone is never a finding.
