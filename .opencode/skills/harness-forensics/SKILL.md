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

### Parser pick

| Format | Tool | Missing |
|---|---|---|
| pcap | tshark | not-tested |
| memory | vol3 + known ISF | not-tested |
| disk | fls/icat read-only | not-tested |
| EVTX | EvtxECmd | not-tested |

```
cyber_process argv=["sha256sum","<artifact>"]
cyber_process argv=["tshark","-r","<pcap>","-q","-z","io,phs"]
```

One claim per observation (connection, process, path). Clean fixture or outside time window is the negative control. Do not execute the sample. Hash mismatch vs intake → stop.

### Stop

Live acquire without approval, RW mount, "run it in a VM".

### Evidence ids

Hash, parser line, clean-twin control, `cyber_source` artifact.

### Reproduction recipe

Hash must match intake before any parser. One parser, one question, quoted tool line. Clean fixture or outside window must not show the same marker. Filename is not execution. Redact PII the claim does not need. Chain to ghidra/secret-scan only for a named extracted file. Do not mount RW. Do not execute. If the hash diverges from intake, stop — wrong object.

A DNS name in a pcap is not C2 until a second source agrees. A process name without the tool line is a hypothesis.

Intake hash, parser, control: three ids. Missing parser → `not-tested`, not a guessed timeline.

Do not carve the whole disk "in case". One path or one flow per finding.

## Done

Evidence holds the hash and the parser output. No claim without a tool-returned line. An unparsed format stays `not-tested`.
