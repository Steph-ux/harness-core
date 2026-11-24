---
name: harness-voip
description: "Assess an approved SIP/RTP PBX: OPTIONS/banner, one REGISTER or INVITE as the test extension, no toll fraud, no production blast."
---

# VoIP — OPTIONS, one test extension, no toll fraud

Source: SIP RFC 3261, RTP. Toll fraud and war-dialing are out.

## Gate

PBX/SBC host and **test extension** named in scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **No INVITE to PSTN, no REGISTER flood, no RTP inject on live calls.** Lab or maintenance window only.

## Steps

### 1. Banner

```
cyber_process argv=["nmap","-sV","-Pn","-p","5060,5061","<approved-host>"]
```

SIP/TLS identity observation. Missing nmap → `not-tested`.

### 2. OPTIONS / one REGISTER

```
cyber_process argv=["sipsak","-S","-s","sip:<test>@<host>"]
```

or a single REGISTER as the **test** extension. Record status. Do not try `1000-9999`.

### 3. Negative control

A random extension not in the test list must `404`/`403`. OPTIONS to a second host not in scope must not be sent. Same `200 OK` on an unused AoR is not "open PBX".

### 4. Media

If RTP is in scope, **hash a pcap already collected** — do not tap a live call. Cleartext RTP with audio of a **test** call is a candidate; real-user audio is out.

### 5. Finding contract

`cyber_finding` for: unauthenticated SIP, default extension, TLS missing on 5060 with a captured test REGISTER — plus the unused-extension control. CVE on Asterisk/FreeSWITCH via `cyber_cve` on the **exact** version. No finding that required a PSTN call.

## Proof contract

Unauthenticated SIP or a default extension needs the banner/REGISTER observation and the unused-extension 404/403. A PSTN INVITE is never the proof.

## Done

Evidence holds banner, one test REGISTER/OPTIONS, unused-extension control. No toll fraud.
