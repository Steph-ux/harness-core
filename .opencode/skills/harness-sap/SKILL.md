---
name: harness-sap
description: "Enumerate an approved SAP landscape read-only: SID, ICM/gateway/RFC exposure, ICF services, client; no transport, no user create, no production write."
---

# SAP — landscape enum, read-only

Source: SAP ICM, gateway, RFC, ICF, SAP Security Notes. Production change is out.

## Gate

SID, client, and host must be named in scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No `tp import`, no user create, no debug in production, no RFC that writes, no default-password spray on a live landscape. Lab/sandbox only for exploit confirmation.

## Steps

### 1. Identity

Record SID, client, instance numbers, ICM HTTP(S) ports already in evidence.

```
cyber_process argv=["nmap","-sV","-Pn","-p","3200,3300,3600,8000,44300,50000,50013","<approved-host>"]
```

Own observation. Missing nmap → `not-tested`.

### 2. ICM / ICF surface

If HTTP(S) is in scope, one GET on documented ICF paths (`/sap/public/info`, `/sap/bc/gui/sap/its/webgui`) with the **test** identity. Record status + body hash. Do not iterate the whole SICF tree.

### 3. Gateway / RFC

Banner/version only:

```
cyber_process argv=["nmap","-sV","-Pn","-p","<approved-rfc-port>","<approved-host>"]
```

If the probe binary is absent, record `not-tested`. Do not call `RFC_READ_TABLE` on production unless the scope **names** that RFC and a row limit.

### 4. Negative control

A closed instance number, or a client the test user must not enter, must 401/refuse. Same body as a successful client is the finding, not a control.

Default users (`SAP*`, `DDIC`) are **candidates** until a login is **explicitly** approved on a **non-prod** client. Never try them on production.

### 5. Notes vs findings

SAP Security Note / CVE: `cyber_cve lookup` on the **exact** kernel/ICM version. Version string without lookup is not a finding.

### 6. Finding contract

`cyber_finding` with identity scan, one ICM/RFC observation, negative control (wrong client/closed port), source chunk (note or ICF path). Write operations are out.

### Instance table

| Port | Role | This method |
|---|---|---|
| 8000/44300 | ICM HTTP(S) | one ICF GET |
| 3300/3600 | gateway/RFC | banner only |
| 3200 | dispatcher | identity |
| 50013 | SAP Start Service for instance 00 | verify configured identity |

```
cyber_process argv=["nmap","-sV","-Pn","-p","3200,3300,3600,8000,44300,50000,50013","<approved-host>"]
```

Wrong client / closed instance = negative control. `SAP*`/`DDIC` only on named non-prod. No `tp import`, no user create.

### Stop

Production write, RFC_READ_TABLE without named RFC+row limit, default-password spray.

### Evidence ids

Scan, one ICM/RFC read, wrong-client control. Notes via `cyber_cve` on exact kernel version.

### ICF one GET

Documented path only (`/sap/public/info` or `/sap/bc/gui/sap/its/webgui`) with the **test** identity. Do not walk the whole SICF tree. RFC_READ_TABLE only if named + row limit.

```
cyber_process argv=["nmap","-sV","-Pn","-p","3200,3300,3600,8000,44300,50000,50013","<approved-host>"]
```

Wrong client / closed instance = negative control. Notes via `cyber_cve` on exact kernel.

### Stop

`tp import`, user create, production debug, default-password spray.

## Verification scenarios

Derive instance-specific ports from the approved inventory; examples are not a port map for every landscape.
Separate ICM, RFC gateway, dispatcher, message server and SAP Start Service.
Record SID, client, instance number, kernel release and patch level independently.

| Scenario | Observation | Expected classification |
|---|---|---|
| Public ICF info path returns documented public metadata | service policy and body | not automatically an auth bypass |
| WebGUI shows only a login form | content and session identity | exposed login, not SAP access |
| Approved test identity is denied a restricted synthetic client | client and security decision | negative control |
| Port 50013 identifies SAP Start Service | banner and instance inventory | do not label it message server |
| Security Note excludes the installed patch level | component and note applicability | advisory mismatch |

A closed TCP port validates transport behavior, not SAP client authorization.
RFC_READ_TABLE needs an explicit table, row limit and permitted synthetic fields.
Use only a known installed RFC client; a made-up probe executable is not a test.
Attach client binding, read-only response, exact component applicability and denial evidence.
Record inaccessible Security Notes as unavailable instead of guessing their fixes.

## Done

Evidence holds SID/client identity, one read-only surface observation, and a control. Unprobed instance numbers stay `not-tested`.
