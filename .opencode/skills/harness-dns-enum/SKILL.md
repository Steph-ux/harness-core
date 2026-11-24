---
name: harness-dns-enum
description: "Collect DNS records for an approved zone and attempt one bounded AXFR per approved nameserver; refused transfers are controls, not findings."
---

# DNS — records then one AXFR per approved NS

Source: RFC 5936, delegated NS, dnsx. AXFR still appears on mis-delegated servers.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Query only the approved zone and its delegated NS. Any other server is a stop. Do not change DNS. Do not query names learned from AXFR until they pass scope filtering.

## Steps

### 1. Inventory records

From DNS events already in evidence, or:

```
cyber_process argv=["dnsx","-silent","-a","-aaaa","-cname","-mx","-txt","-ns","-caa","-resp","-l","<zone-file>"]
```

List NS/A/AAAA/CNAME/MX/TXT/CAA/SOA for the approved zone. Record resolver, timestamp, TTL.

### 2. One AXFR per approved NS

```
cyber_process argv=["dig","AXFR","<zone>","@<approved-ns>","+time=5","+tries=1"]
```

Each NS is its own observation. Five-second timeout, one retry maximum.

### 3. Negative controls

`Transfer failed` / `REFUSED` / timeout = **negative controls**, not findings. Also query:
- the **wrong zone** on the same NS
- a **non-delegated** NS

Those must not return the in-scope zone.

### 4. Success path

Success = zone records returned. Ingest via `cyber_source`. Do not probe transferred hostnames until each name is inside the approved apex. Confirm with a second NS or `dnsx -resp`.

Takeover / dangling NS is a **hypothesis** until current DNS plus an independent confirmation (`harness-subdomain-enum`).

### 5. Finding contract

`cyber_finding` needs:
- AXFR observation that returned records
- source chunk of the record set
- second NS or dnsx confirmation
- refused/wrong-zone observation as negative control

### Query budget

| Query | Max |
|---|---|
| dnsx inventory | 1 |
| AXFR per approved NS | 1, +time=5 +tries=1 |
| wrong-zone on same NS | 1 control |
| non-delegated NS | 1 control |
| brute | 0 this method |

```
cyber_process argv=["dnsx","-silent","-a","-aaaa","-cname","-mx","-txt","-ns","-caa","-resp","-l","<zone-file>"]
cyber_process argv=["dig","AXFR","<zone>","@<approved-ns>","+time=5","+tries=1"]
```

REFUSED/timeout = negative control, not a finding. Names from AXFR stay unprobed until scope filter. Takeover → second method.

### Stop

Changing DNS, querying off-apex, treating AXFR refuse as vuln.

### Evidence ids

Inventory, each AXFR, refuse/wrong-zone control, source chunk if transfer succeeded.

### Reproduction recipe

One AXFR per approved NS, 5s, one retry. REFUSED is a control. Success = records returned, then scope-filter before any probe. Wrong-zone on the same NS must not return the in-scope zone.

## Done

Every approved NS has one recorded AXFR result. Only a transfer that returns records is a misconfiguration.
