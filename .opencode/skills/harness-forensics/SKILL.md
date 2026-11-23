---
name: harness-forensics
description: "Examine a memory, disk, or packet artifact already collected in an engagement, hash first, and record only what the tool output shows."
---

# Forensics — collected artifact, hash first

## Gate

The artifact must already be in `<evidence-dir>`. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Do not acquire a live system unless that acquisition is separately approved. Do not execute a sample.

## Steps

1. `sha256sum` the artifact and record the identity observation before any parser runs.
2. Parse with the tool that matches the format already present: `tshark` for a pcap, Volatility only when installed and the image profile is known, or a file listing for a disk image. A missing parser is `not-tested`.
3. Extract one claim at a time: a connection, a process, a timestamp, or a file path. Quote the tool line. A filename is not execution.
4. Negative control: the same parser on a known-clean fixture, or a time window outside the claimed event, must not show the same marker.
5. `cyber_finding` needs the hash, the parser observation, the negative control, and the artifact chunk via `cyber_source`. Redact personal data that the claim does not need.

## Done

Evidence holds the hash and the parser output. No claim without a tool-returned line.
