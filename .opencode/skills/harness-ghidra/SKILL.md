---
name: harness-ghidra
description: "Headless Ghidra on a hashed engagement binary: program info, two-needle string/import search, address-cited decompile and xrefs to a real sink, benign-function control. Never execute."
---

# Ghidra — headless first, address-cited only

Source: analyzeHeadless / Ghidra MCP. Strings without xrefs are hypotheses.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Headless first. GUI only if the operator already opened the program. Binary must belong to the engagement. Missing Ghidra/Java → `not-tested`. Do not execute, emulate, patch, unpack malware "to see", or fetch samples.

## Steps

### 1. Hash then import

```
cyber_process argv=["sha256sum","<binary>"]
cyber_process argv=["file","<binary>"]
cyber_process argv=["support/analyzeHeadless","<project>","<name>","-import","<binary>","-analysisTimeoutPerFile","300"]
```

Positive control: program info (name, image base, SHA256). Wrong hash → stop.

### 2. Record the matrix

Architecture, format, compiler hints, entry, imports/exports. Each from tool output, not guess.

### 3. Search with two needles

```
list_strings --contains <needle-a>
list_strings --contains <needle-b>
list_imports
list_functions --regex <re>
```

Quote every `0x...` the tool returned. No address = hypothesis. Absence of needle-a ≠ "not present" until needle-b also misses.

### 4. Decompile the cited address

`decompile` / `disassemble` at `0x...`. A string is not a sink. Confirm xrefs to `system` / `exec` / `strcpy` / `recv` / `connect` / crypto APIs. Function names in the decompiler are hypotheses until the address is returned.

### 5. Negative control

A **known-benign** function in the same binary (string compare, init) must not support the same sink claim. Same xref set on the benign function rejects the claim.

### 6. Finding contract

`cyber_finding` evidence = hash + import log + search + decompile + xrefs + benign control. `cyber_source` = decompiler chunk at `file? no — address`. Checks: xrefs reproduction, benign-function negative-control. Do not follow network IOCs from strings.

### Address budget

| Query | Need |
|---|---|
| program info | name+base+SHA256 |
| strings | two needles |
| imports | listed |
| decompile | cited 0x |
| xrefs | to real sink |
| benign fn | negative control |

```
cyber_process argv=["sha256sum","<binary>"]
cyber_process argv=["support/analyzeHeadless","<project>","<name>","-import","<binary>","-analysisTimeoutPerFile","300"]
```

No address = hypothesis. Missing Ghidra → `not-tested`. Do not execute the sample.

### Stop

Emulate, patch, fetch samples, follow C2 from strings.

### Evidence ids

Hash, import log, search, decompile, xrefs, benign-function control.

## Done

Every claim cites a Ghidra observation and a `0x...` address. No claim without a tool-returned address.
