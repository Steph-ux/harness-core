---
name: harness-dns-enum
description: "Collect DNS records and test zone transfer only for an approved nameserver and zone."
---

# DNS — records then one AXFR per approved NS

Source: `performing-dns-enumeration-and-zone-transfer` (2025: AXFR still live on mis-delegated NS).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Query only the approved zone and its delegated NS. Any other server is a stop.

## Steps

1. From `bbot` DNS events already in evidence, list `NS/A/AAAA/CNAME/MX/TXT/CAA` for the approved zone; if absent, run the passive `subdomain-enum` preset and read its DNS events.
2. For each approved NS, one AXFR attempt, bounded:
```text
dig AXFR <zone> @<approved-ns> +time=5 +tries=1
# argv: dig, AXFR, <zone>, @<ns>, +time=5, +tries=1
```
Record each as its own observation.

3. `Transfer failed` / `REFUSED` / timeout = negative controls, not findings.
4. Success = zone records returned. Store the record set, ingest via `cyber_source`, and do not query transferred names until each name is inside the approved scope. `cyber_finding` needs the AXFR observation + the source chunk + a second NS or a `dnsx -resp` confirmation observation.

### Record correlation

Compare NS, SOA serial, A/AAAA/CNAME, MX, TXT, CAA and DNSSEC indicators with
the approved inventory. Preserve resolver, timestamp and TTL. A delegation or
takeover hypothesis requires current DNS plus an independent confirmation.

### Safety controls

Use one AXFR attempt per approved NS, five-second timeout and one retry maximum.
The wrong-zone query, a non-delegated NS, and a refused transfer are negative
controls. Never alter DNS or query names learned from AXFR until scope filtering
is complete.

## Done

Every approved NS has one recorded AXFR result. Only a transfer that returns records is a misconfiguration.
