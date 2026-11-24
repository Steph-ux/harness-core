---
name: harness-network-pivot
description: "From an approved foothold, run bounded discovery then one unauth and one lowest-privilege probe per in-scope service; no Internet-wide brute, no destructive lateral."
---

# Network pivot

Source: internal enumeration, one-hop lateral. The foothold is named; the Internet is not.

## Gate

An approved foothold or VPN/jump host must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Stay inside engagement boundaries. Brute (`naabu`/`nmap`/`ffuf`) only when the scope explicitly allows it. No dump/exploit beyond permanent authorizations. No DoS.

## Steps

### 1. Inventory from the foothold

Interfaces, routes, DNS already in evidence — one observation.

### 2. Bounded discovery (approved segment only)

```
cyber_process argv=["naabu","-host","<segment-or-host>","-top-ports","1000","-o","<evidence-dir>/naabu.txt"]
cyber_process argv=["nmap","-sV","--top-ports","1000","<approved-host>","-oN","<evidence-dir>/nmap.txt"]
```

Passive first when possible (`bbot -rf passive`). Do not `-p-` the RFC1918 of a customer.

### 3. Unauth probe per service

Repeat each discovered **in-scope** service once without a credential. `401`/`403`/`connection refused` is the negative control, not a finding.

### 4. One credentialed probe

Same service, lowest-privilege identity already in scope (`smbclient`, `ldapsearch`, `curl`, `ssh -o BatchMode=yes`). Record banner/status. Do not spray. Do not pass a non-test identity.

### 5. One lateral hop only if allowed

Source and destination observations. Candidate until `harness-vuln-triage`. `cyber_capture` linked to the session observation if a desktop session is the proof.

Entities: foothold → route → host → service → identity.

### 6. Finding contract

`cyber_finding` with unauth + auth observations, source chunks, checks. No finding from a scan alone. Stop on unexpected segmentation, unnamed host, or a destructive command.

## Done

Evidence holds bounded scan outputs and two observations per claimed service (unauth + auth). A pivot is a finding only after the second host's evidence.
