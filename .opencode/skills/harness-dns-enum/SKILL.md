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

Each NS is its own observation. Five-second timeout, one try and no retry.

### 3. Negative controls

`REFUSED` is a possible negative control; timeout is inconclusive transport failure.
Only where separately approved, also query:
- a **synthetic nonexistent zone** on the same NS
- another **in-scope** NS configured to deny transfers

Those must not return the in-scope zone.

### 4. Success path

Success = a complete transfer with matching opening/closing SOA for the requested
zone and serial. Partial records are not completion. Ingest via `cyber_source`.
Do not probe transferred names until each passes scope filtering.
Confirm with a second approved NS or `dnsx -resp`.

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
| approved deny-transfer NS | 1 control |
| brute | 0 this method |

```
cyber_process argv=["dnsx","-silent","-a","-aaaa","-cname","-mx","-txt","-ns","-caa","-resp","-l","<zone-file>"]
cyber_process argv=["dig","AXFR","<zone>","@<approved-ns>","+time=5","+tries=1"]
```

REFUSED is a negative control; timeout is not a denial. Names from AXFR stay unprobed until scope filter. Takeover → second method.

### Stop

Changing DNS, querying off-apex, treating AXFR refuse as vuln.

### Evidence ids

Inventory, each AXFR, refuse/wrong-zone control, source chunk if transfer succeeded.

### Reproduction recipe

One AXFR per approved NS, 5s, one try. REFUSED is a control. Success = complete records returned, then scope-filter before any probe. A synthetic wrong-zone control must not return the in-scope zone.

## Verification scenarios

Use a delegated lab zone with known public records and a deny-transfer twin.
Store full DNS response flags and RCODE, not just the last line from dig.
`+tries=1` means one try; do not describe it as one additional retry.

| Scenario | Evidence | Expected result |
|---|---|---|
| AXFR starts but connection closes early | opening SOA without closing SOA | incomplete transfer |
| Complete zone returns to an unauthorized client | matching first/last SOA and records | exposure candidate |
| Deny-transfer twin replies REFUSED | answered TCP request | negative control |
| TCP connection times out | connection trace and deadline | transport not-tested |
| DNS answer changes between resolvers | TTL, resolver and timestamp | reconcile before ownership claim |

An AXFR finding needs the access policy; deliberately public transfers are not automatically flawed.
Keep authoritative DNS, recursive cache and split-horizon views distinct.
Do not register a dangling name or cloud resource to confirm a takeover here.
Attach zone serial, server identity, completeness and denied-transfer observations.

### Executed local regression

`node test/opencode-skill-fixtures.cjs` sends AXFR queries over loopback TCP.
It checks a complete two-message transfer, REFUSED, early EOF, mismatched closing
SOA serial and a real socket deadline. Timeout stays not-tested, never denied.
The client supports only uncompressed synthetic names; it is not a production DNS parser.
The dig recipe's bounded flags are checked, but the dig binary is not executed.
Resolver diversity, DNSSEC, TSIG and real zone policies remain unvalidated.

## Done

Every approved NS has a recorded result or explicit not-tested reason.
Only a complete unauthorized transfer contrary to the zone policy is an exposure finding.
