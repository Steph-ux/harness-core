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
cyber_process argv=["nwrfcsdk-probe"] 
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
| 50013 | message server | identity |

```
cyber_process argv=["nmap","-sV","-Pn","-p","3200,3300,3600,8000,44300,50000,50013","<approved-host>"]
```

Wrong client / closed instance = negative control. `SAP*`/`DDIC` only on named non-prod. No `tp import`, no user create.

### Stop

Production write, RFC_READ_TABLE without named RFC+row limit, default-password spray.

### Evidence ids

Scan, one ICM/RFC read, wrong-client control. Notes via `cyber_cve` on exact kernel version.

## Done

Evidence holds SID/client identity, one read-only surface observation, and a control. Unprobed instance numbers stay `not-tested`.
