---
name: harness-subdomain-enum
description: "Passive subdomain enum of an approved apex: three sources, merge, dnsx re-resolve, CT cross-check; no brute; one-source names stay candidates."
---

# Subdomain — passive-only, dedup + re-resolve

Source: BBOT, Amass, subfinder, dnsx. Brute is out of this pass.

## Gate

Approved scope must include the apex. Every command goes through `cyber_process` with `argv`. Do not build a shell string. `BBOT --no-deps`. No `dnsbrute`, `naabu`, `ffuf` here. Do not probe names absent from the apex.

## Steps

### 1. Three passive sources

Each its own observation:

```
cyber_process argv=["bbot","-t","<apex>","-p","subdomain-enum","-rf","passive","-em","dnsbrute","dnsbrute_mutations","--no-deps","-y","--json","-o","<evidence-dir>"]
cyber_process argv=["amass","enum","-d","<apex>","-passive","-o","<evidence-dir>/amass.txt"]
cyber_process argv=["subfinder","-d","<apex>","-all","-o","<evidence-dir>/subfinder.txt"]
```

Missing tool → `not-tested` for that source, continue with the others.

### 2. Merge

Unique, only `*.apex`. Rest = out-of-scope. Normalize trailing dots, IDN/punycode, case. Observation for `candidates.txt`.

### 3. Re-resolve

```
cyber_process argv=["dnsx","-l","<evidence-dir>/candidates.txt","-resp","-o","<evidence-dir>/dnsx.json"]
```

Only dnsx-resolved names advance. NXDOMAIN stays candidate.

### 4. CT cross-check

Names in CT (`harness-ct-logs`) but absent from dnsx are **not live**. Do not register a dangling CNAME.

### 5. Negative control

Keep: one out-of-scope name, one NXDOMAIN, one name seen in only one source. Two independent passive sources must agree before `confirmed`.

### 6. Finding contract

This method does **not** create `cyber_finding`. Takeover/exposure → DNS/web/triage with live obs. A CNAME to a cloud provider is a pivot lead, not ownership.

### Name states

| State | Meaning |
|---|---|
| candidate | seen in ≥1 passive source |
| in-scope | under approved apex after normalize |
| resolved | dnsx answered |
| live | httpx/tls later, not this method |
| not-tested | tool missing or brute forbidden |

Two sources must agree before `confirmed`. A CT-only name is not live.

### Merge rules

Trailing dots, IDN/punycode, case fold before unique. Only `*.apex`. CNAME to a cloud provider is a pivot lead, not ownership — do not register it.

Missing bbot/amass/subfinder → `not-tested` for that source, continue. Two remaining sources can still confirm.

```
cyber_process argv=["dnsx","-l","<evidence-dir>/candidates.txt","-resp","-o","<evidence-dir>/dnsx.json"]
```

This method does not file `cyber_finding`. Takeover/exposure needs live obs from DNS/web/triage.

### Stop

dnsbrute, naabu, ffuf, probing off-apex, treating CT-only as live.

### Evidence ids

Each passive tool, candidates.txt, dnsx. Out-of-scope, NXDOMAIN, one-source names kept as controls.

## Done

Subdomain list cites three tool observations + dnsx. One-source or non-apex names stay candidates.
