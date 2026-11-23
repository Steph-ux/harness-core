---
name: harness-network-pivot
description: "Pivot from an approved foothold using bounded port/service discovery and safe lateral checks without destructive actions."
---

# Network pivot

Source: `performing-internal-network-enumeration`, `pivoting-techniques`.

## Gate

An approved foothold or VPN/jump host must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No brute across the whole Internet; stay inside the engagement `blacklist` / `boundaries`. Brute (naabu/nmap/ffuf) only when the scope explicitly allows it. Dumps and exploitation follow the permanent authorizations (`dump + CVE` sauf DoS/DDoS/availability).

## Steps

1. Inventory: from the foothold, list interfaces, routes, and DNS names already in evidence. Record one observation for the inventory command.
2. Bounded discovery inside the approved segment only:

```text
naabu -host <segment-or-approved-host> -top-ports 1000 -o <evidence-dir>/naabu.txt
nmap -sV --top-ports 1000 <approved-host> -oN <evidence-dir>/nmap.txt
```

Or via BBOT when the foothold can reach the apex: `bbot -t <apex> -rf passive --no-deps -y --json -o <evidence-dir>` — passive first.

3. Repeat each discovered service once without a credential (or with the lowest-privilege credential already in scope). A 401/403 or `connection refused` is the negative control.
4. One credentialed probe per service (smb, ldap, http, ssh) with the approved identity. Record the status and banner; do not spray.
5. One lateral move only when the scope allows it (e.g. `smbclient`, `ldapsearch`, or `ssh` with the approved key). Record the source and destination observations; a successful move is a candidate until `harness-vuln-triage` confirms persistence and `cyber_capture` attests the session (linked to its observation id).

Every finding is `cyber_finding` with its `evidence` observation ids, `sources` chunk ids (via `cyber_source`), and `checks`. No finding from a scan alone.

### Pivot graph

Represent the foothold, interface, route, destination, service, identity and
result as entities and relations. Expand one hop at a time within the approved
CIDR/host list. An open port is a candidate; prove access with the lowest-
privilege credential and a harmless read-only query.

### Controls and stopping rules

Use an unreachable approved address, a closed port and an unauthenticated
service response as controls. Stop on unexpected segmentation, a credential
prompt for a non-test identity, a destructive command, or an unnamed host.

## Done

The evidence directory holds the bounded scan outputs and the two observations per service (unauth + auth). A pivot is only a finding after the second host's evidence.
