---
name: harness-ghidra
description: "Inspect a local binary already open in Ghidra and record only functions, strings, and cross-references that the tool output shows."
---

# Ghidra — headless first, address-cited only

Source: `reverse-engineering-malware-with-ghidra`. Use Ghidra MCP or `analyzeHeadless`. Do not fetch samples. Do not execute.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
**Headless first.** Prefer `ghidra-mcp --headless --binary <file> --project /tmp/cve-lab-*` (PyGhidra) or `support/analyzeHeadless <project> <name> -import <binary>`. GUI `http://127.0.0.1:8080/` only when operator opened a program. Confirm via `get_program_info` (name+base+hash) before any address. Binary must belong to engagement.

## Steps

1. `get_program_info` → positive control (`name+base+SHA256`). If headless, also record `analyzeHeadless` import log.
2. Search behavior: `list_strings --contains <needle>`, `list_imports`, `list_functions --regex <re>`. Quote `0x...` returned — no address = hypothesis.
3. `decompile --address 0x...` / `disassemble` at that address. String ≠ sink — confirm `list_cross_references --address 0x...` to `system/exec/strcpy/decrypt/socket/connect`.
4. Record tool-call observation ids. Each capability/persistence/network conclusion needs cited instruction+string+xrefs. `set_bookmark` is navigation only.
5. `cyber_finding` with `evidence`=info+search+decompile+xrefs, `sources`=decompiler chunk via `cyber_source`, `checks`=xrefs reproduction. Absence ≠ not present — try two needles.

### Analysis matrix

Record architecture, format, compiler hints, entry points, imports/exports,
strings, permissions, network APIs, crypto APIs, process/file APIs and error
paths. Trace a claim from a returned address to decompilation, disassembly and
cross-references; function names and guessed symbols are hypotheses until the
tool returns the address. Inspect both a likely-positive and a known-benign
function as a negative control.

### Safety and reproducibility

Hash the binary before import and keep the project isolated. Do not execute,
emulate, patch, fetch missing samples or follow network indicators. Use one
address-based query at a time, cite tool output and record the analysis version.
If Ghidra/Java is unavailable, report the binary as `not-tested` rather than
substituting an unverified decompiler.

## Done

Every claim cites Ghidra observation + `0x...` address. No claim without tool-returned address.
