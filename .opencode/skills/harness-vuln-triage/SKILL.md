---
name: harness-vuln-triage
description: "Decide whether a scanner hit or HTTP 200 is a confirmed finding: claimed effect in the body, fresh reproduction, negative control, or it stays a lead."
---

# Triage — 200 ≠ finding

Source: error pages that return 200 are the #1 false positive. Scanner severity is not CVSS.

## Gate

One reproduction of an already approved request. Every command via `cyber_process` `argv` when a repro is needed. Do not promote nuclei/dalfox/trivy severity by itself. Do not use response time alone.

## Steps

### 1. One-sentence claim

Plus offered observation ids. `cyber_memory` / evidence them — the body must show the claimed data or state change, **not only status**.

### 2. Name the negative control before the repro

Examples: unauth 401/403, wrong id 404, tampered JWT 401, recomputed price 400. None recorded → **candidate**, no finding.

### 3. Reproduce once

```
cyber_process argv=["curl","-sS","-D","-","-H","X-Request-Id: <fresh>","<approved-url>"]
```

Fresh request-id only. Same relevant field must appear. New observation id. Preserve status, content-type, body hash.

### 4. Visual if needed

Stored XSS rendering, receipt total, state banner: `cyber_capture` **linked** to the reproduction observation. No id = refused. Capture never replaces the HTTP/CLI observation.

### 5. Classify

- **confirmed** — claimed effect in body/state/callback/capture + control differs
- **candidate** — signal exists, control or runtime proof missing
- **false positive** — control explains it
- **not-tested** — scope or tooling blocked repro

### 6. Finding contract

`cyber_finding` only when original + control + reproduction agree, with `checks` each `observationId` + `contains` (leaked field / persisted state, not status) + `purpose`, plus `sources` via `cyber_source`. Map OWASP/MITRE only when the behavior supports it. Name what was **not** proven.

## Done

Ledger is either a finding (three citations) or an explicit candidate with the missing control named.
