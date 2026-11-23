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
```text
bbot -t <apex> -p subdomain-enum -rf passive --strict-scope --no-deps -y --dry-run
bbot -t <apex> -p subdomain-enum -rf passive --strict-scope --no-deps -y --json -o <evidence-dir>
amass enum -d <apex> -passive -o <evidence-dir>/amass.txt
subfinder -d <apex> -all -o <evidence-dir>/subfinder.txt
```
Merge → `candidates.txt` (dedup, only `*.apex` parent kept; rest out-of-scope).

### B — DNS resolution
```text
dnsx -l <evidence-dir>/candidates.txt -resp -o <evidence-dir>/dnsx.json
```
Only resolved names advance. Unresolved stays candidate.

### C — Liveness and TLS
```text
httpx -l <evidence-dir>/candidates.txt -tls-probe -cname -tech-detect -json -o <evidence-dir>/httpx.json
tlsx -l <evidence-dir>/httpx.json -o <evidence-dir>/tlsx.json
```
No `200/3xx` and no valid TLS = not live.

### D — Historical URLs
```text
waymore -i <apex> -mode U -oU <evidence-dir>/waymore.txt
gau --threads 5 <apex> > <evidence-dir>/gau.txt
# dedup → historic-urls.txt — every URL is a lead
```

### E — Crawl and params (live hosts in scope only)
```text
katana -u https://<live-host> -jc -o <evidence-dir>/katana.txt
hakrawler -url https://<live-host> -depth 2
cariddi -intense -plain -target https://<live-host>
paramspider -d <apex>
arjun --url https://<live-host>/ --passive -oT <evidence-dir>/arjun.txt
gf xss <evidence-dir>/katana.txt  # 23 patterns in ~/.gf
```
Normalize → `endpoints.json` (`method + path template + host + params`).

### F — Deep source + vuln scan (on the same evidence)
```text
semgrep --config p/javascript --config p/xss --config p/command-injection --include="*.js" --json -o <evidence-dir>/semgrep.json <evidence-dir>
nuclei -l <evidence-dir>/httpx.json -t ~/nuclei-templates/http/cves/ -o <evidence-dir>/nuclei-cves.json
nuclei -l <evidence-dir>/httpx.json -o <evidence-dir>/nuclei.json
gitleaks detect --source <evidence-dir> --report-format json --report-path <evidence-dir>/gitleaks.json --no-banner --exit-code 0
trufflehog filesystem <evidence-dir> --json --no-verification > <evidence-dir>/trufflehog.json
trivy fs <evidence-dir> --format json --output <evidence-dir>/trivy.json --quiet
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

## Done

Evidence holds the full pipeline outputs; ledger lists only in-scope assets with observation ids. A tool finding event is not a vulnerability.
