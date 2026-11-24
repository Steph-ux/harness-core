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

Use an offline clean fixture or vendor-approved simulator denial as the negative control.
Registers and PLCs outside scope remain unqueried; that exclusion is not a control observation.

### 5. Finding contract

`cyber_finding` only for a documented boundary violation, credential exposure or
applicable version issue, with the poll/hash observation and an executed matching control.
**Never** a finding that required a write to prove.

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

Timeout → stop, no retry loop. Keep unnamed registers outside coverage, not as tested controls.

### Stop

Coil write, PLC stop/start, firmware, safety-network scan, radio jamming.

### Evidence ids

Protocol identity, at most one poll and offline/simulator control. A write is a method violation. Banner ≠ CVE until `cyber_cve` matches the exact version.

Process-safety owner named in scope or stop.

### Safety owner

Process-safety owner must be named. If in doubt, stop. Full cell port-sweep only with named range **and** maintenance window.

```
cyber_process argv=["mbpoll","-1","-a","<unit>","-r","<reg>","<approved-plc>"]
```

Timeout → stop, no retry loop. Use the simulator for denial controls. Radio → `harness-wireless`.

### Stop

Coil write, PLC stop/start, firmware, safety-network scan, jamming.

## Verification scenarios

An unpolled point is a scope boundary, not an observed negative control.
Prefer offline traffic and a vendor-approved simulator for negative comparisons.
Confirm register type, address base, count and endian interpretation before a poll.
The mbpoll example omits device-specific settings; resolve them with the safety owner.

| Scenario | Observation | Expected classification |
|---|---|---|
| Known simulator point returns the documented value | unit, register and decoder output | parser positive control |
| Simulator denies a protected synthetic node | same protocol and identity | negative control |
| One-based and zero-based registers are confused | project map and requested offset | invalid probe |
| Historian returns cached measurements | timestamp and source | no proof of a fresh PLC read |
| Live device times out once | deadline and owner notification | stop; availability state unknown |

Plain Modbus without authentication needs network/control-policy context for impact.
An exposed engineering service is not proof that write access was obtained.
Record safety owner, maintenance window, source file and exact permitted point.
Attach actual comparison evidence; never label non-execution as a passed test.
Unexercised protocol branches remain explicitly not-tested.

## Done

Evidence holds protocol identity, at most one approved poll, and a control. Any write attempt is a method violation, not a test.
