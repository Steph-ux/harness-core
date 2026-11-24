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
cyber_process argv=["sqlite3","<lab-db>","SELECT count(*) FROM <table>"]
```

### 4. Negative control

Unmodified config/DB must not show the mutated state. A second machine without the client must not be scanned. Same "admin" flag in a demo DB is not privilege on production.

### 5. Finding contract

`cyber_finding` with hash, inventory observation, one mutation observation, unmodified control, source chunk (config path or decompile). Authz bugs in the **server** API behind the client → `harness-idor` / `harness-api-testing` with HTTP observations, not this method alone.

Secrets in config → `harness-secret-scan`. Native bugs → `harness-ghidra`.

## Done

Evidence holds binary hash, local surface list, one mutation + control. No production crash, no crack.
