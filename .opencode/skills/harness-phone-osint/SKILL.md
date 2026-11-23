---
name: harness-phone-osint
description: "Gather public information on an approved phone number using PhoneInfoga, recording the source and the result."
---

# Phone — PhoneInfoga + second source, no scrape

Source: PhoneInfoga 0.1, `osint-deep` (2025: public HLR, no `*` expansion).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Phone in canonical `+<cc><number>`, named in scope. No carrier scrape/brute without approval. No premium API unless cost approved.

## Steps

1. `cyber_process` `argv`:
```text
phoneinfoga scan -n <phone-number> -o <evidence-dir>/phoneinfoga.txt
```
Own observation. Second tool e.g. `holehe`/`theHarvester` on derived email already in evidence.

2. Record `carrier, country, line type`, public listing. Candidate until second source confirms (same number + `email/name/address` from `maigret`/`holehe` or breach corpus).
3. No auto-dialers/SMS oracles/`*` expansion. Extracted emails/names stay leads — each needs its own scope.
4. `cyber_finding` only with two observations + `cyber_source` chunk. Hash any sensitive token, never raw.

### Correlation and controls

Normalize E.164 format, country and line type. Separate carrier metadata,
public listing, breach hit and identity correlation; they are different claims.
Use a known-unused number and a near-match as negative controls. Never call,
send SMS, trigger an OTP, enumerate wildcard numbers, or test a discovered
credential. New names/emails remain leads until separately scoped.

## Done

Evidence holds PhoneInfoga output. Confirmed cites two observations + source.
