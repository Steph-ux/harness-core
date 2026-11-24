---
name: harness-vuln-triage
description: "Promote a scanner hit or HTTP 200 only when the claimed effect is in the body, a fresh reproduction matches, and a named negative control differs."
---

# Triage — 200 ≠ finding

Source: error pages that return 200. Scanner severity is not CVSS.

## Gate

One reproduction of an already approved request. Every command via `cyber_process` `argv` when a repro is needed. Do not promote nuclei/dalfox/trivy by itself. Do not use timing alone.

## Steps

### 1. One-sentence claim

Plus offered observation ids. Evidence them: the body must show the claimed data or state change, **not only status**.

### 2. Name the control first

Examples: unauth `401`, wrong id `404`, flipped JWT `401`, recomputed price `400`. None recorded → **candidate**, no finding.

### 3. Reproduce once

```
cyber_process argv=["curl","-sS","-D","-","-H","X-Request-Id: <fresh>","<approved-url>"]
```

Fresh request-id. Same relevant field. New observation. Preserve status, content-type, body hash.

### 4. Visual if needed

Stored XSS, receipt total, banner: `cyber_capture` **linked** to the reproduction. No id = refused. Capture never replaces HTTP/CLI.

### 5. Classify

- **confirmed** — effect in body/state/callback/capture + control differs
- **candidate** — signal exists, control or runtime missing
- **false positive** — control explains it
- **not-tested** — scope or tooling blocked repro

### 6. Finding contract

`cyber_finding` only when original + control + reproduction agree. Each check: `observationId` + `contains` (field/state, not status) + `purpose`. Sources via `cyber_source`. Map OWASP/MITRE only when the behavior supports it. Name what was **not** proven.

### What never promotes

Scanner severity, HTTP 200, response time, WAF 403, reflected canary without execution, OpenAPI "might be IDOR". Those stay candidates or false positives.

### Freshness

The reproduction observation must be after the original claim observation. Reusing the scanner's request id is not a fresh repro.

### Classification table

| Class | Body/state | Control | Action |
|---|---|---|---|
| confirmed | claimed effect | differs | cyber_finding |
| candidate | signal | missing | no finding |
| false positive | explained | matches noise | close |
| not-tested | blocked | n/a | name the gap |

```
cyber_process argv=["curl","-sS","-D","-","-H","X-Request-Id: <fresh>","<approved-url>"]
```

Reproduction after the original claim. Capture linked to repro if visual. `contains` is the field, not `200`.

### Stop

Promoting nuclei severity, timing-only, reusing scanner id as repro.

### Evidence ids

Original, named negative control, fresh reproduction.

## Done

Ledger is a finding (three citations) or an explicit candidate with the missing control named.
