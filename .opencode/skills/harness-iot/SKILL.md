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

An interface **not** in scope, or a closed port on the same device, must not be queried or reported as exposed. A version string in a banner is not a CVE until `cyber_cve lookup` says the **exact** version is affected.

### 5. Finding contract

`cyber_finding` needs:
- firmware hash observation
- unpack or interface observation
- negative control (out-of-scope iface or unflagged version)
- source chunk (extracted config, not the whole image)

Hardcoded key in firmware: the finding is the **key material in the image**, not a claim you authenticated to the live fleet.

### Unpack then one live probe

```
cyber_process argv=["sha256sum","<firmware.bin>"]
cyber_process argv=["binwalk","-e","-M","<firmware.bin>"]
cyber_process argv=["nmap","-sV","-Pn","-p","<port>","<approved-host>"]
```

Native blob → `harness-ghidra`. Secret string → `harness-secret-scan`. Lockfile → `harness-supply-chain`. Radio → `harness-wireless`. One banner/TLS/HTTP/MQTT/SNMP named OID. Closed/out-of-scope iface is the negative control. Version ≠ CVE until lookup.

### Stop

Jamming, deauth, firmware write, UART brute, live RCE, default-password spray on a fleet.

### Evidence ids

Firmware hash, unpack or interface, out-of-scope iface control, source chunk.

### Reproduction recipe

Hash firmware first. Unpack read-only. One live probe if an iface is named. Closed/out-of-scope iface is the control. Banner version waits for `cyber_cve`. No radio in this method.

## Done

Evidence holds the firmware hash and the interface or unpack result. An unparsed format stays `not-tested`. No live exploit, no radio disruption.
