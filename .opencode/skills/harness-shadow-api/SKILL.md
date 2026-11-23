---
name: harness-shadow-api
description: "Identify an API route that is absent from the documented contract but present in collected client traffic or responses."
---

# Shadow API — doc vs observed, one live probe

Source: `detecting-shadow-api-endpoints` (2024: OpenAPI diff + client crawl).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Search evidence already collected: `openapi.json`/`swagger.json`, `endpoints.json` from `harness-source-deep`, `katana -jc`/`hakrawler`/`cariddi`/`paramspider`/`arjun`/`gf`, `waymore`/`gau`, HAR, BBOT URL events. Wordlist brute (`ffuf`/`gobuster`/`dirsearch`) only when the engagement explicitly allows content discovery and never outside the approved boundaries.

## Steps

1. List documented routes from the contract (`openapi.json` / GraphQL schema / vendor doc) — `cyber_source` that file. Normalize `method + path template + host` into `documented.txt`.
2. Extract observed routes from the same evidence that `harness-attack-surface` E already produced, plus `gf` + `arjun` on live hosts in scope → `observed.txt`.
3. Diff: `observed − documented` on the same `host` = shadow candidates. A route on an out-of-scope host is not a shadow — note it as out-of-scope.
4. One live probe per shadow candidate when `host + method` are approved (`cyber_process` `argv`, e.g. `curl -s -o /tmp/out -w "%{http_code}" https://host/path`). Record the `code + body + hdrs` observation.
5. `404` = not a shadow. `200` = needs `harness-vuln-triage` (is the body a real resource or an error page with `200`? — `harness-skill-gate.md` rule 7). One shadow → one `cyber_finding` with `evidence` = contract observation + observed-list observation + live-probe observation, `sources` = contract chunk + crawl chunk, `checks` = documented-absence:positive-control, live-200:reproduction.

### Normalization matrix

Normalize method, scheme, host, path casing, trailing slash, percent encoding,
query keys, version prefix and GraphQL operation name before diffing. Keep
authentication and content type in the record. A route is shadow only when the
observed and documented hosts are the same and the difference survives
normalization; a stale archive, a redirect, an asset path, or a framework
health route is not enough.

### Safe probe and negative control

Use `HEAD` or a harmless `GET` first, then one approved method/body only when
the scope names it. Compare the shadow response with a known-invalid sibling
path and the documented equivalent. Record status, content type, body hash,
redirect target and authentication requirement. Never mutate state merely to
prove that an undocumented route exists.

### Proof contract

The result distinguishes route existence, undocumented exposure and actual
impact. Only the first two can be reported from a bounded probe; authorization,
data exposure and state changes require their own method (`harness-access-control`,
`harness-idor` or `harness-business-logic`) and separate observations.

## Done

Each shadow route cites the contract and the traffic/crawl observation plus the live probe. A 200 alone is never a finding.
