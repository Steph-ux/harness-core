---
name: harness-shadow-api
description: "Diff documented OpenAPI/GraphQL routes against observed traffic; one harmless live probe per in-scope shadow candidate; 200 is not impact."
---

# Shadow API — doc vs observed, one live probe

Source: OpenAPI diff, client crawl, HAR. A stale archive URL is not a shadow.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Search evidence already collected. Wordlist brute only when the engagement explicitly allows content discovery and never outside approved hosts. Do not mutate state merely to prove a route exists.

## Steps

### 1. Documented contract

`cyber_source` the `openapi.json` / GraphQL schema / vendor doc. Normalize `method + path template + host` → documented set.

### 2. Observed routes

From attack-surface evidence, katana/HAR/BBOT URL events, same host. Normalize casing, slash, encoding, version prefix, GraphQL operation name.

### 3. Diff

`observed − documented` on the **same host** = shadow candidates. Out-of-scope host ≠ shadow.

### 4. One live probe per candidate

HEAD or harmless GET first:

```
cyber_process argv=["curl","-sS","-D","-","-o","NUL","-X","HEAD","<approved-url>"]
```

Record status, content-type, body hash, auth requirement. `404` = not a shadow. `200` → `harness-vuln-triage` (real resource vs error page with 200).

Negative control: known-invalid sibling path on the same host.

### 5. Finding contract

One shadow → one `cyber_finding` with contract observation + observed-list + live probe + documented-absence control. Impact (IDOR, data, state) is **another** method (`harness-idor`, `harness-access-control`, `harness-business-logic`).

## Done

Each shadow route cites the contract, the crawl observation, and the live probe. A 200 alone is never a finding.
