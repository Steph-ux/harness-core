---
name: harness-forensics
description: "Examine a memory, disk or packet artifact already collected: hash first, parse with the matching tool, one claim per observation, clean-twin control."
---

# Forensics — collected artifact, hash first

Source: NIST SP 800-86, Volatility, tshark. Acquisition of a live system is a separate approval, not this method.

## Gate

The artifact must already be in the engagement evidence directory. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Do not acquire a live system unless that acquisition is separately approved. Do not execute a sample. Do not mount a disk image read-write. Do not "just run it in a VM" to see what it does.

## Steps

### 1. Hash before any parser

```
cyber_process argv=["sha256sum","<artifact>"]
```

Record size and type (`file` magic) as the identity observation. If the hash does not match the intake note, stop — you are not looking at the seized object.

### 2. Pick one parser for the format that is actually there

| Format | Tool (if present) | Missing tool |
|---|---|---|
| pcap / pcapng | `tshark` | `not-tested` |
| memory image | Volatility 3 with a **known** profile/ISF | `not-tested` |
| disk image | listing / `fls` / `icat` read-only | `not-tested` |
| EVTX / syslog | EvtxECmd / `jq` on JSON export | `not-tested` |

```
cyber_process argv=["tshark","-r","<pcap>","-q","-z","io,phs"]
cyber_process argv=["vol","-f","<mem>","windows.pslist"]
```

Do not chain five plugins "in case". One parser, one question.

### 3. One claim per observation

Extract **one** of: a connection, a process, a timestamp, a file path, an autorun. Quote the tool line verbatim. A filename on disk is not execution. A DNS name in a pcap is not C2 until a second source agrees.

Redact personal data the claim does not need (emails, names) before it reaches a finding.

### 4. Negative control

The same parser on:
- a known-clean fixture of the same format, or
- a time window **outside** the claimed event

must not show the same marker. Same PID/name on the clean image rejects the claim that it is "the malware".

### 5. Finding contract

`cyber_finding` needs:
- hash observation
- parser observation (quoted line)
- negative-control observation
- artifact registered via `cyber_source`

Chain to `harness-secret-scan` or `harness-ghidra` only for a **named** file already extracted, not the whole image.

## Done

Evidence holds the hash and the parser output. No claim without a tool-returned line. An unparsed format stays `not-tested`.
