---
name: harness-thick-client
description: "Assess an approved desktop client (Win32, WPF, Electron, Java): hash, local config/IPC/traffic, one mutation; no production crash, no license crack."
---

# Thick client — hash, local surface, one mutation

Source: thick-client pentest (config, IPC, update, local DB). License bypass and crashing other users' clients are out.

## Gate

The installer/binary must be in evidence; the test OS is a **named lab**. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No license crack, no patching a production binary, no fuzzing until crash on a shared terminal server.

## Steps

### 1. Identity

```
cyber_process argv=["sha256sum","<client.exe>"]
cyber_process argv=["file","<client.exe>"]
```

Electron → `asar` list if present. Java → jar list. .NET → `monodis`/`ilspycmd` if present. Missing tool → `not-tested` for that stack.

### 2. Local surface inventory

Config files, local DB, named pipes, COM, localhost ports, update URL — from the lab profile, not guessed:

```
cyber_process argv=["ss","-lntp"]
```

or Windows `netstat`. Record listening localhost. Traffic to an approved update host: `harness-headers` / TLS via `harness-crypto-tls`.

### 3. One mutation

Pick **one**: local DB row, IPC message, or update XML. Change one field. Observe client behavior. Do not brute IPC.

```
cyber_process argv=["sqlite3","-readonly","<lab-db>","SELECT count(*) FROM <table>"]
```

### 4. Negative control

Unmodified config/DB must not show the mutated state. A second machine without the client must not be scanned. Same "admin" flag in a demo DB is not privilege on production.

### 5. Finding contract

`cyber_finding` with hash, inventory observation, one mutation observation, unmodified control, source chunk (config path or decompile). Authz bugs in the **server** API behind the client → `harness-idor` / `harness-api-testing` with HTTP observations, not this method alone.

Secrets in config → `harness-secret-scan`. Native bugs → `harness-ghidra`.

### Stack table

| Stack | Inventory | Next |
|---|---|---|
| Electron | asar list | source-deep / secret-scan |
| .NET | ilspycmd if present | ghidra if native |
| Java | jar tf | source-deep |
| Win32 | strings + localhost ports | ghidra |

```
cyber_process argv=["sha256sum","<client.exe>"]
cyber_process argv=["sqlite3","-readonly","<lab-db>","SELECT count(*) FROM <table>"]
```

One mutation (config, IPC, or update XML). Unmodified copy is the negative control. Server IDOR behind the client → `harness-idor`.

### Stop

License crack, fuzz-to-crash on a terminal server, production binary patch.

### Evidence ids

Hash, inventory, one mutation, unmodified control.

### One mutation

Config row, IPC message, or update XML — one field. Unmodified copy is the negative control.

```
cyber_process argv=["sha256sum","<client.exe>"]
cyber_process argv=["sqlite3","-readonly","<lab-db>","SELECT count(*) FROM <table>"]
```

Electron asar / .NET ilspy / Java jar if present, else `not-tested` for that stack. Server bugs behind the client → `harness-idor`. Secrets → `harness-secret-scan`.

### Stop

License crack, fuzz-to-crash on a shared terminal server, production binary patch.

## Verification scenarios

Record installer signature, binary hash, user privilege and actual running version.
Use an isolated profile and copy local databases with their WAL/SHM state consistently.
Keep local UI changes separate from effective server-side privileges.

| Scenario | Observation | Expected classification |
|---|---|---|
| Local `admin=true` exposes a button but server denies it | UI and actual API response | cosmetic change, no server escalation |
| Untrusted local actor reaches a privileged IPC action | pipe/socket ACL and effect | local privilege boundary candidate |
| Same IPC request from an unprivileged twin is denied | actor and ACL result | negative control |
| Update metadata changes but signed package verification rejects it | update log and signature decision | update integrity holds |
| Read-only DB command fails because file is absent | path and exit status | no accidental empty database creation |

An ASAR archive is packaging, not an authenticity or privilege boundary.
Check named-pipe/localhost origin authentication rather than assuming loopback is trusted.
Do not feed extracted untrusted code into the operator host's interpreter.
Attach mutation bytes, before/after effect and the unmodified-profile control.
Leave signing-bypass and binary memory-corruption claims to separately scoped lab tests.

## Done

Evidence holds binary hash, local surface list, one mutation + control. No production crash, no crack.
