---
name: harness-attack-surface
description: "Map an approved external domain with a bounded passive pipeline (BBOT, Amass, subfinder, dnsx, httpx, waymore, gau, katana, hakrawler, cariddi, nuclei, gitleaks) and record assets in the engagement ledger."
---

# Attack surface — passive pipeline deep

Source: `implementing-attack-surface-management` (BBOT 3.0.2, Amass 4.2.0) + ProjectDiscovery inventory from `harness-skill-gate.md`. The pipeline is the installed gate — do not add tools outside it.

## Gate

Approved scope only. Every command goes through `cyber_process` with `argv`. `BBOT --no-deps -y`. A name emitted by a tool is a candidate, not a target, until the scope includes it. Port/dir brute (`naabu`, `ffuf`, `gobuster`) only when the scope explicitly allows it. Amounts stay reversible (1 XOF pattern).

## Steps (each step writes into `<evidence-dir>` and is its own observation)

### A — Passive enumeration

```
cyber_process argv=["bbot","-t","<apex>","-p","subdomain-enum","-rf","passive","--strict-scope","--no-deps","-y","--json","-o","<evidence-dir>"]
cyber_process argv=["amass","enum","-d","<apex>","-passive","-o","<evidence-dir>/amass.txt"]
cyber_process argv=["subfinder","-d","<apex>","-all","-o","<evidence-dir>/subfinder.txt"]
```
Merge → `candidates.txt` (dedup, only `*.apex` parent kept; rest out-of-scope).

### B — DNS resolution

```
cyber_process argv=["dnsx","-l","<evidence-dir>/candidates.txt","-resp","-o","<evidence-dir>/dnsx.json"]
```
Only resolved names advance. Unresolved stays candidate.

### C — Liveness and TLS

```
cyber_process argv=["httpx","-l","<evidence-dir>/candidates.txt","-tls-probe","-cname","-tech-detect","-json","-o","<evidence-dir>/httpx.json"]
cyber_process argv=["tlsx","-l","<evidence-dir>/httpx.json","-o","<evidence-dir>/tlsx.json"]
```
Any attributable HTTP response, including 401/403/404, supports HTTP liveness.
Certificate validity is a separate property; invalid TLS does not mean the host is down.

### D — Historical URLs

```
cyber_process argv=["waymore","-i","<apex>","-mode","U","-oU","<evidence-dir>/waymore.txt"]
cyber_process argv=["gau","--threads","5","<apex>"]
```

### E — Crawl and params (live hosts in scope only)

```
cyber_process argv=["katana","-u","https://<live-host>","-jc","-o","<evidence-dir>/katana.txt"]
cyber_process argv=["hakrawler","-url","https://<live-host>","-depth","2"]
cyber_process argv=["paramspider","-d","<apex>"]
cyber_process argv=["arjun","--url","https://<live-host>/","--passive","-oT","<evidence-dir>/arjun.txt"]
```
Normalize → `endpoints.json` (`method + path template + host + params`).

### F — Deep source + vuln scan (on the same evidence)

```
cyber_process argv=["nuclei","-l","<evidence-dir>/httpx.json","-t","~/nuclei-templates/http/cves/","-o","<evidence-dir>/nuclei-cves.json"]
cyber_process argv=["nuclei","-l","<evidence-dir>/httpx.json","-o","<evidence-dir>/nuclei.json"]
cyber_process argv=["gitleaks","detect","--source","<evidence-dir>","--redact=100","--report-format","json","--report-path","<restricted-output-dir>/gitleaks.json","--no-banner","--exit-code","0"]
cyber_process argv=["trivy","fs","<evidence-dir>","--format","json","--output","<evidence-dir>/trivy.json","--quiet"]
```
Every hit is a candidate. Needs `harness-vuln-triage` / `harness-secret-scan` / `harness-source-deep` before a finding.

### G — Ledger
One observation per tool + one per parsed list. `cyber_source` ingest `candidates.txt`, `dnsx.json`, `httpx.json`, `endpoints.json`, `taint-inventory.json`. Ledger assets = only in-scope names/URLs/endpoints with observation ids. `cyber_capture` for any visual proof (e.g. `httpx` tech stack page).

### Correlation and gap logic

Treat every candidate as `(name, source, resolution, liveness, TLS, scope)`.
Confirm an asset only when it is in scope, resolves, and has a successful
liveness/TLS observation; a single source, CT name, CNAME or HTTP 200 is not
enough. When a pipeline tool is missing, mark only that branch `not-tested`,
retain the other sources, and do not silently substitute a different scanner.

### Negative controls

Keep an out-of-scope hostname, an unresolved candidate, a known closed host and
an invalid TLS/HTTP response as controls. Historical URLs remain leads until
the current host re-serves the path; scanner hits remain candidates until
`harness-vuln-triage`.

### Finding contract

The attack-surface method records assets and candidates; it does not create a
`cyber_finding` from enumeration alone. A finding must cite the relevant
pipeline observations, source chunks and reproduction/positive-control/
negative-control checks from the owning deep method.

## Verification scenarios

Treat the text blocks above as tool inventories, not shell scripts to execute.
Discover installed CLI input formats before composing the argv for each stage.
Store stdout in the owned process trace; use native output options rather than redirection.

```
cyber_process argv=["httpx","-u","https://<approved-host>","-json"]
```

| Scenario | Observation | Expected result |
|---|---|---|
| In-scope host returns 403 with expired TLS | HTTP and certificate records | live, restricted, TLS issue separate |
| Historical URL now serves a generic error | current invalid-sibling comparison | historical lead only |
| JSON scanner output is fed to a URL-list tool | input schema check | convert/validate first, not empty coverage |
| Redirect or CNAME leaves approved scope | normalized target and scope decision | do not follow actively |
| Parser accepts an off-apex fixture | label-boundary test | reject parser result |

Extract URL lines for nuclei and host:port lines for tlsx instead of assuming JSON compatibility.
Use an observed lab NXDOMAIN/soft-404 as control; merely excluding a hostname is not a test.
Record source outages and parser failures separately from a successful empty inventory.
Attach the stage provenance chain so every live asset can be traced to actual responses.

## Done

Evidence holds the full pipeline outputs; ledger lists only in-scope assets with observation ids. A tool finding event is not a vulnerability.
