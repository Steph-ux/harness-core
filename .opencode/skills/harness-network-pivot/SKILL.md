---
name: harness-network-pivot
description: "From an approved foothold: inventory, bounded scan of the named segment, unauth then lowest-priv probe per in-scope service; one hop; no Internet-wide brute."
---

# Network pivot — one hop, two probes per service

Source: internal enum. The foothold is named; RFC1918 of a stranger is not.

## Gate

Approved foothold or VPN/jump in scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Brute only if the scope says so. No dump/exploit beyond authorizations. No DoS. Stop on unnamed host or unexpected segmentation.

## Steps

### 1. Inventory

Interfaces, routes, DNS already in evidence — one observation from the foothold.

### 2. Bounded discovery

Approved segment only:

```
cyber_process argv=["naabu","-host","<segment-or-host>","-top-ports","1000","-o","<evidence-dir>/naabu.txt"]
cyber_process argv=["nmap","-sV","--top-ports","1000","<approved-host>","-oN","<evidence-dir>/nmap.txt"]
```

Passive first (`bbot -rf passive`) when possible. No `-p-` of a whole customer 10/8.

### 3. Unauth probe

Each **in-scope** service once without a credential. `401`/`403`/`refused` = negative control, not a finding.

### 4. Lowest-priv probe

Same service, approved identity (`smbclient`, `ldapsearch`, `curl`, `ssh -o BatchMode=yes`). Record banner/status. Do not spray. Do not use a non-test identity.

### 5. One lateral hop if allowed

Source + destination observations. Candidate until `harness-vuln-triage`. Desktop session → `cyber_capture` linked to that obs. Entities: foothold → route → host → service → identity.

### 6. Finding contract

`cyber_finding` with unauth + auth obs, source chunks. No finding from a scan alone. Unreachable approved address and closed port are extra controls.

### Hop budget

One hop per pass. A second hop is a new method load with a new foothold name. SOCKS/`proxychains` only if the jump host is the approved foothold. Internet-wide `naabu` is a method violation.

### Stop

Unexpected VLAN, credential prompt for a non-test identity, unnamed host, or a tool that writes (psexec, wmiexec) without a named authorization.

## Done

Evidence holds bounded scans and two observations per claimed service (unauth + auth). A pivot is a finding only after the second host's evidence.
