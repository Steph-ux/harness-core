---
name: harness-ics-ot
description: "Read-only assessment of an approved ICS/OT segment: identify protocol, one poll of a named point, never write coils, never disrupt process."
---

# ICS/OT — identify, poll once, never write

Source: IEC 62443, NIST SP 800-82. Process safety beats the finding.

## Gate

Plant, cell, and protocol must be named in scope, with a **process-safety owner**. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **No coil/register write. No firmware. No PLC stop/start. No scan of a safety network.** If in doubt, stop.

## Steps

### 1. Identify, do not flood

From a historian/PCAP already collected, or one bounded read:

```
cyber_process argv=["tshark","-r","<pcap>","-Y","modbus or dnp3 or enip","-T","fields","-e","frame.protocols"]
```

Record protocol (Modbus/TCP, DNP3, EtherNet/IP, OPC-UA, S7). A full port-sweep of the cell is out unless the owner named the range **and** a maintenance window.

### 2. One named point

If a live poll is approved, **one** read of a **named** address (unit id + register, OPC node):

```
cyber_process argv=["mbpoll","-1","-a","<unit>","-r","<reg>","<approved-plc>"]
```

Missing tool → `not-tested`. Timeout → stop, do not retry in a loop.

### 3. Asset identity

Firmware/version from the read or from a collected project file (`cyber_source`). `cyber_cve lookup` on that exact version. Banner ≠ CVE.

### 4. Negative control

A register/node **not** in the named list must not be polled. A second PLC not in scope must not be contacted. Same value on an unused register is not "the process".

### 5. Finding contract

`cyber_finding` only for: default/no auth on an engineering port, cleartext credentials in a collected project, version with a matching lookup — each with the poll/hash observation and the unpolled-point control. **Never** a finding that required a write to prove.

Wireless/radio on the plant → `harness-wireless` with OT gate, not this method.

### Protocol table (identify, then one poll)

| Protocol | Identify | One read |
|---|---|---|
| Modbus/TCP | pcap / mbpoll | named unit+register |
| DNP3 | tshark filter | named point |
| EtherNet/IP | tshark enip | named tag |
| OPC-UA | documented node | Browse one node |
| S7 | banner only | no write |

```
cyber_process argv=["tshark","-r","<pcap>","-Y","modbus or dnp3 or enip","-T","fields","-e","frame.protocols"]
cyber_process argv=["mbpoll","-1","-a","<unit>","-r","<reg>","<approved-plc>"]
```

Timeout → stop, no retry loop. Unnamed register must not be polled (negative control).

### Stop

Coil write, PLC stop/start, firmware, safety-network scan, radio jamming.

### Evidence ids

Protocol identity, at most one poll, unpolled-point control. A write is a method violation. Banner ≠ CVE until `cyber_cve` matches the exact version.

## Done

Evidence holds protocol identity, at most one approved poll, and a control. Any write attempt is a method violation, not a test.
