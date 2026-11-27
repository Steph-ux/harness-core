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

`cyber_finding` for: unauthenticated SIP, default extension, TLS missing on 5060 with a captured test REGISTER — plus the unused-extension control. CVE on Asterisk/FreeSWITCH via `cyber_cve search` (NVD + searchsploit) on the **exact** version (or `cyber_cve lookup` for OSV packages). No finding that required a PSTN call.

## Proof contract

Unauthenticated SIP or a default extension needs the banner/REGISTER observation and the unused-extension 404/403. A PSTN INVITE is never the proof.

### Probe budget

| Probe | Max |
|---|---|
| OPTIONS/REGISTER | 1 test extension |
| Extension brute | 0 |
| PSTN INVITE | 0 |
| RTP tap of live call | 0 — hash collected pcap only |

```
cyber_process argv=["nmap","-sV","-Pn","-p","5060,5061","<approved-host>"]
```

Unused extension must 404/403.

### TLS

5061 vs 5060: missing TLS on 5060 with a captured **test** REGISTER is a candidate. Version string → `cyber_cve search` on exact Asterisk/FreeSWITCH version (or `cyber_cve lookup` for OSV packages).

```
cyber_process argv=["sipsak","-S","-s","sip:<test>@<host>"]
```

Missing sipsak → OPTIONS via nmap script if present, else banner-only `not-tested` for REGISTER. RTP: hash a collected pcap, do not tap a live call. Real-user audio is out.

### Stop

INVITE to PSTN, REGISTER flood, extension brute 1000-9999, RTP inject.

### Evidence ids

Banner, one test REGISTER/OPTIONS, unused-extension negative control.

### Reproduction recipe

OPTIONS/one test REGISTER, unused extension 404. No PSTN, no flood.

## Verification scenarios

Record SIP transport, SBC route, Call-ID and test address-of-record.
Check sipsak's installed help: its command example is an OPTIONS-style probe,
not proof that a REGISTER transaction occurred.
Use an operator-listed unused extension; do not choose random subscriber numbers.

| Scenario | Observation | Expected classification |
|---|---|---|
| OPTIONS gets 200 without authentication | method and Allow headers | protocol reachability, not open registration |
| REGISTER receives a 401/407 challenge | complete transaction and WWW/Proxy-Authenticate | authentication requested |
| Approved test registration fails with invalid credentials | matching test transaction | negative control |
| UDP 5060 is filtered while TCP responds | per-transport probes | distinguish transport coverage |
| Collected test-call pcap contains SRTP | SDP and media format | do not call encrypted payload clear audio |

Digest challenge material is not a plaintext password.
Plain SIP on 5060 is not alone proof of credential disclosure or toll fraud.
Version banners may be masked by an SBC; bind advisories to the actual component.
Attach correlated transactions and actual access/transport policy, not status alone.
Call placement, live media capture and PSTN remain outside this bounded probe.

## Done

Evidence holds banner, one test REGISTER/OPTIONS, unused-extension control. No toll fraud.
