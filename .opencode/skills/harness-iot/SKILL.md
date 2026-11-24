---
name: harness-iot
description: "Assess an approved IoT or embedded device from collected firmware and one read-only interface probe, without radio disruption or a live exploit."
---

# IoT — collected firmware and approved interface

Source: OWASP IoT, NIST IR 8259, binwalk/firmware-mod-kit read-only. Radio jamming, deauth, and live RCE are out.

## Gate

The device, firmware image, and interface must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No jamming, no deauthentication, no firmware write, no UART/JTAG brute, no exploit against the live device, no default-password spray on a production fleet.

## Steps

### 1. Identity

Hash the firmware image and record device model / serial **already on the label or intake**:

```
cyber_process argv=["sha256sum","<firmware.bin>"]
cyber_process argv=["file","<firmware.bin>"]
```

Completion: SHA256 is in evidence. If the file is not firmware (HTML, empty), stop.

### 2. Unpack read-only

```
cyber_process argv=["binwalk","-e","-M","<firmware.bin>"]
```

Inventory file types: squashfs, kernel, web root, certs, `passwd`, keys. Do not flash. Do not emulate to get a shell unless that sandbox is named in scope as a **separate** method.

A native binary → `harness-ghidra`. A secret string → `harness-secret-scan`. A lockfile → `harness-supply-chain`.

### 3. One read-only live probe (if an interface is in scope)

Exactly one of: banner, TLS cert, HTTP `/`, MQTT CONNECT to an **approved** broker, or SNMP GET of a **named** OID.

```
cyber_process argv=["nmap","-sV","-Pn","-p","<port>","<approved-host>"]
cyber_process argv=["openssl","s_client","-connect","<host>:<port>","-servername","<name>"]
```

Record the response hash. No community-string guessing. No radio (`aireplay`, `ubertooth`) in this method — that is `harness-wireless` with its own gate.

### 4. Negative control

An out-of-scope interface remains unqueried. Use a clean offline firmware fixture
or an approved interface's actual denial response for the negative control.
A banner needs exact version/advisory applicability before a CVE claim.

### 5. Finding contract

`cyber_finding` needs:
- firmware hash observation
- unpack or interface observation
- executed negative control (clean firmware fixture or permitted interface denial)
- source chunk (extracted config, not the whole image)

Hardcoded key in firmware: the finding is the **key material in the image**, not a claim you authenticated to the live fleet.

### Unpack then one live probe

```
cyber_process argv=["sha256sum","<firmware.bin>"]
cyber_process argv=["binwalk","-e","-M","<firmware.bin>"]
cyber_process argv=["nmap","-sV","-Pn","-p","<port>","<approved-host>"]
```

Native blob → `harness-ghidra`. Secret string → `harness-secret-scan`. Lockfile → `harness-supply-chain`. Radio → `harness-wireless`. One named interface probe with an actual fixture/denial control. Version ≠ CVE until lookup.

### Stop

Jamming, deauth, firmware write, UART brute, live RCE, default-password spray on a fleet.

### Evidence ids

Firmware hash, unpack or interface, executed fixture/denial control, source chunk.

### Reproduction recipe

Hash firmware first. Unpack read-only. One named live probe if approved.
Use a clean fixture or actual denial as control. Banner version waits for `cyber_cve`.

## Verification scenarios

Record firmware model, hardware revision, vendor version and intake origin.
Extract only into a disposable directory with parser resource limits.
An untouched out-of-scope interface is not an executed negative control.

| Scenario | Evidence compared | Expected classification |
|---|---|---|
| Firmware contains a vendor public certificate | certificate purpose and path | public material, not a secret |
| Sample configuration includes a nonfunctional test password | fixture provenance | scanner negative control |
| Private management request is denied without credentials | approved interface and response | access-control negative control |
| Image version differs from the live device | label/project vs runtime identity | no transferred CVE claim |
| Unpacker reports a filesystem without extracting it | parser log and directory | incomplete analysis |

An MQTT CONNECT may change broker session state; use a disposable client id.
SNMP read-only claims require the permitted OID and credential, not community guessing.
Firmware secure boot, update signatures and rollback remain separate unexercised branches.
Attach actual control responses; scope exclusions belong in coverage limitations.
Report extracted secrets separately from any claim about live authentication.

## Done

Evidence holds the firmware hash and the interface or unpack result. An unparsed format stays `not-tested`. No live exploit, no radio disruption.
