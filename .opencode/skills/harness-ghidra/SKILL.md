---
name: harness-ghidra
description: "Inspect a local binary already in evidence with headless Ghidra: hash, program info, address-cited decompile and xrefs; never execute the sample."
---

# Ghidra — headless first, address-cited only

Source: Ghidra headless / analyzeHeadless. Do not fetch samples. Do not execute.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. **Headless first.** GUI only when the operator already opened a program. Binary must belong to the engagement. If Ghidra/Java is unavailable: `not-tested`, do not substitute an unverified decompiler.

## Steps

### 1. Hash then import

```
cyber_process argv=["sha256sum","<binary>"]
cyber_process argv=["support/analyzeHeadless","<project>","<name>","-import","<binary>","-analysisTimeoutPerFile","300"]
```

Positive control: `get_program_info` (name + base + SHA256). Wrong hash → stop.

### 2. Search behavior

`list_strings --contains <needle>`, `list_imports`, `list_functions --regex <re>`. Quote `0x...` the tool returned. No address = hypothesis, not a finding.

### 3. Decompile at that address

`decompile --address 0x...` / `disassemble`. A string is not a sink. Confirm `list_cross_references --address 0x...` to `system`/`exec`/`strcpy`/`recv`/`connect`. Function names are hypotheses until the tool returns the address.

### 4. Negative control

Inspect a **known-benign** function in the same binary (e.g. a string compare with no xrefs to exec). It must not support the same sink claim.

### 5. Finding contract

`cyber_finding` with evidence = info + search + decompile + xrefs, `cyber_source` decompiler chunk, checks = xrefs reproduction + benign-function control. Absence of a string ≠ "not present" — try two needles. Do not emulate, patch, or follow network IOCs.

## Done

Every claim cites a Ghidra observation and a `0x...` address. No claim without a tool-returned address.
