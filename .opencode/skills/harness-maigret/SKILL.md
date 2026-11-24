---
name: harness-maigret
description: "Correlate one approved username with Maigret or Sherlock on a bounded site set; a 200 is not a profile; confirm with a second attribute."
---

# Maigret+Sherlock — bounded, two-source

Source: Maigret, Sherlock. First pass is top-sites only.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Username in approved scope. No `--permute`, `--all-sites`, `--enrich`, `--with-domains` on the first pass. Do not contact accounts. Do not bypass rate limits.

## Steps

### 1. Bounded scan

```
cyber_process argv=["maigret","<username>","--no-autoupdate","--no-recursion","--top-sites","100","--timeout","15","-n","20","-J","simple","-fo","<evidence-dir>"]
cyber_process argv=["sherlock","<username>","--timeout","15","--print-found","--output","<evidence-dir>/sherlock.txt"]
```

Each is its own observation.

### 2. Classify each URL

unavailable / claimed / found / confirmed. Check final URL, body marker, profile title. A 200 or a generic login page is **not** a profile. The searched username must appear as the account, not as a search result.

`cyber_source` the JSON/HTML chunk for found URLs only.

### 3. Second attribute

Same username + email/name/photo hash from an independent `osint-deep` source. One hit is not confirmation. Each discovered extra username/email is a **new** scope item.

### 4. Negative control

A **known-unused** username and a **near-match** must not produce the same "found" set. Record both.

### 5. Finding contract

`cyber_finding` only with Maigret/Sherlock observation + second source + source chunk + unused-username control. Store URLs and public markers, not private messages or tokens.

## Done

Evidence holds Maigret JSON and/or Sherlock text. Confirmed cites two observations + chunk + control.
