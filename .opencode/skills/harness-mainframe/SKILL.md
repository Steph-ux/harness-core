---
name: harness-mainframe
description: "Read-only assessment of an approved z/OS or IBM i host: TN3270/TN5250 banner, one named transaction or library, no JCL submit, no production write."
---

# Mainframe — banner, one named transaction, no JCL

Source: z/OS RACF/ACF2, TN3270, IBM i. Production batch submit is out.

## Gate

LPAR/system name, VTAM applid or IBM i host, and test identity must be in scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **No `SUBMIT`, no `STRQSH` write, no RACF change, no default-password spray on production.** Lab/sandbox only for any auth probe.

## Steps

### 1. Identity

```
cyber_process argv=["nmap","-sV","-Pn","-p","23,992,322","<approved-host>"]
```

Record TN3270/TN5250/FTP banner. Missing nmap → `not-tested`.

### 2. One named transaction or library

If a 3270/5250 test is approved, **one** inquiry transaction the test user is allowed to run (e.g. a documented lookup). Record screen hash via the approved emulator log, not a screenshot of real customer PII.

```
cyber_process argv=["x3270if","Query","Host"]
```

If the emulator is absent: stop at banner (`not-tested` for apps).

### 3. Dataset / library listing only if scoped

Read-only catalog list (`LISTCAT` / `DSPLIB`) of a **named** HLQ. Do not dump PAYROLL.

### 4. Negative control

A transaction or HLQ **not** in the named list must not be opened. A second LPAR not in scope must not be contacted. Same banner on an out-of-scope port is not "the system".

### 5. Finding contract

`cyber_finding` for: unauthenticated TN3270, default applid without RACF, cleartext FTP of a named HLQ — with banner/inquiry observation and denied-transaction control. CVE on z/OS components via `cyber_cve` on the **exact** PTF/version. No finding that required a job submit.

## Proof contract

Unauthenticated TN3270 or a named HLQ over cleartext FTP needs the banner/inquiry observation and the denied-transaction control. A job submit is never the proof.

### Surface table

| Port/service | Action | Forbidden |
|---|---|---|
| TN3270/992 | banner + one inquiry | SUBMIT JCL |
| TN5250 | one DSPLIB named HLQ | STRQSH write |
| FTP 21 | list named HLQ only | GET payroll |
| 3200+ SAP | not this method | n/a |

```
cyber_process argv=["nmap","-sV","-Pn","-p","23,992,322","<approved-host>"]
```

Default users SAP*/DDIC are out unless a **non-prod** client is named. Denied transaction is the negative control.

### Stop

Production password spray, RACF change, job submit, second LPAR.

### Evidence ids

Banner, one inquiry, denied-transaction control. CVE via `cyber_cve` on exact PTF only. No customer PII on a 3270 screenshot.

## Done

Evidence holds banner, at most one inquiry, and a control. No JCL, no production write.
