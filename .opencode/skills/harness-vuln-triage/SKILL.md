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

### Reproduction recipe

Name the control first. Fresh request-id. contains is the field not 200.

## Verification scenarios

Apply this decision table to synthetic or previously collected evidence first.
Changing an observation id does not make an old request a fresh reproduction.
Distinguish technical confirmation from the independent finding-verification stage.

| Scenario | Evidence available | Expected classification |
|---|---|---|
| Scanner reports critical; response is a login page | status 200, no effect | false positive or unsupported |
| Marker appears in the response but never executes | reflected bytes only | candidate, not XSS |
| Effect repeats with a new request and clean control differs | correlated effect observations | technically reproduced |
| Control and reproduction have identical output | different ids, same output | reject verification pair |
| Reproduction cannot run because test identity expired | original signal only | not-tested for reproduction |

For timing, collect interleaved baseline and probe samples before inferring an effect.
For caches, compare authoritative state rather than a stale browser view.
For asynchronous effects, bind callback id, event time and originating request.
Do not equate one failed transport with application rejection.

### Finding packet

Attach claim, original request, fresh reproduction, negative control and limitation.
Use only markers visible in the cited observations.
Keep `cyber_finding` unverified until the harness's independent attestation succeeds.
Human report approval and actual restitution are later, distinct decisions.

## Done

Ledger is a finding (three citations) or an explicit candidate with the missing control named.
